import Java from 'frida-java-bridge';

// Fixed-length capture configuration: Python replaces only the trailing 1 with
// 0 in the packaged bundle, preserving its byte-count headers and source maps.
const NATIVE_HOOKS_ENABLED = 'SCA_NATIVE_HOOKS_ENABLED_1'.endsWith('1');

// Never alter return values, TLS checks, app integrity checks or outgoing requests.
const MAX_EVENTS = 10000;
const MAX_VALUE = 262144;
let sequence = 0;
let emitted = 0;
let stopping = false;
let nativeHookCount = 0;
const activeThreads = new Set();
const hooks = [];
const hooked = new Set();
const nativeModules = new Set();
const sensitive = /authorization|cookie|api[-_]?key|token|secret|password|credential/i;

function status(name, available, detail) {
  send({type:'capability', name, available, detail:String(detail || '')});
}
function emit(kind, value, api, details={}, stack=[]) {
  if (stopping || value === null || value === undefined) return;
  value = String(value);
  if (!value) return;
  if (value.length > MAX_VALUE) {
    status('value_limit', false, api + ': omitted a ' + value.length + '-character value; limit=' + MAX_VALUE);
    return;
  }
  if (++emitted > MAX_EVENTS) {
    if (emitted === MAX_EVENTS + 1) status('event_limit',false,'Maximum event count reached');
    return;
  }
  send({type:'observation', id:++sequence, kind, value, api, details, stack,
        timestamp:new Date().toISOString(), pid:Process.id, tid:Process.getCurrentThreadId()});
}
function javaStack() {
  try {
    return Java.backtrace({limit:24}).frames.map(f=>({class_name:f.className,method:f.methodName,
      file_name:f.fileName || '',line:f.lineNumber || 0,signature:f.signature || ''}));
  } catch (_) { return []; }
}
function guard(fn, api='unknown') {
  const tid = Process.getCurrentThreadId();
  if (activeThreads.has(tid) || stopping) return;
  activeThreads.add(tid);
  try { fn(); } catch (e) { status('hook_callback:'+api,false,String(e)+'\n'+(e.stack || '')); }
  finally { activeThreads.delete(tid); }
}
function byteValue(bytes, start=0, count=null) {
  if (bytes === null) return null;
  count = count === null ? bytes.length-start : count;
  if (count > MAX_VALUE/2) { status('binary_value_limit',false,'Omitted key material exceeding byte budget'); return null; }
  let hex='';
  for (let i=start; i<start+count; i++) hex += ('0'+(bytes[i]&255).toString(16)).slice(-2);
  return hex;
}
function textBytes(bytes) {
  if (bytes === null || bytes.length > MAX_VALUE) return null;
  try {
    const StringClass = Java.use('java.lang.String');
    const text = String(StringClass.$new(bytes,'UTF-8'));
    if (text.includes('\uFFFD') || /[\x00-\x08\x0e-\x1f]/.test(text)) return null;
    return text;
  } catch (_) { return null; }
}
function observeText(kind, text, api, details={}, stack=null) {
  if (text === null || text === undefined) return;
  text=String(text);
  // Scoped decryption/Base64/TLS outputs, never global strings. Preserve readable
  // outputs so unknown provider prefixes and HTTP relative targets reach analysis.
  emit(kind,text,api,details,stack || javaStack());
}
function installJava(className, method, handler) {
  const key=className+'.'+method;
  if (hooked.has(key)) return;
  try {
    const C=Java.use(className);
    let count=0;
    C[method].overloads.forEach(overload=>{
      const types=overload.argumentTypes.map(t=>t.className);
      const returnType=overload.returnType.className;
      overload.implementation=function(...args) {
        // Capture only after a successful original call; preserve its exception and result.
        const result=overload.call(this,...args);
        guard(()=>handler.call(this,args,result,types,key,returnType),key);
        return result;
      };
      count++;
    });
    hooked.add(key);
    status(key,true,count+' overloads'+(className==='javax.crypto.Cipher' ?
      '; readable byte-array return values only; output-buffer and ByteBuffer results are not reconstructed' : ''));
  } catch(e) { /* Optional class may load later. One final capability records absence. */ }
}
function headers(request, api, stack) {
  try {
    const h=request.headers();
    for(let i=0;i<h.size();i++) {
      const name=String(h.name(i));
      if(sensitive.test(name)) emit('header',String(h.value(i)),api,{name},stack);
    }
  } catch(_) {}
}
function installJavaHooks() {
  installJava('java.net.URL','$init',function(args,result,types,api){
    emit('url',String(this.toString()),api,{stage:'constructed'},javaStack());
  });
  installJava('java.net.URL','openConnection',function(args,result,types,api){
    emit('url',String(this.toString()),api,{stage:'connection_requested'},javaStack());
  });
  installJava('java.net.URLConnection','setRequestProperty',function(args,result,types,api){
    if(args.length===2 && sensitive.test(String(args[0])))
      emit('header',String(args[1]),api,{name:String(args[0]),stage:'assigned'},javaStack());
  });
  installJava('java.net.URLConnection','addRequestProperty',function(args,result,types,api){
    if(args.length===2 && sensitive.test(String(args[0])))
      emit('header',String(args[1]),api,{name:String(args[0]),stage:'assigned'},javaStack());
  });
  installJava('android.webkit.WebView','loadUrl',function(args,result,types,api){
    if(args.length) emit('url',String(args[0]),api,{stage:'webview_navigation'},javaStack());
  });
  installJava('android.webkit.WebView','postUrl',function(args,result,types,api){
    if(args.length) emit('url',String(args[0]),api,{stage:'webview_post'},javaStack());
  });
  installJava('okhttp3.OkHttpClient','newCall',function(args,result,types,api){
    if(!args.length) return;
    const request=args[0], stack=javaStack();
    emit('url',String(request.url().toString()),api,{stage:'call_created',method:String(request.method())},stack);
    headers(request,api,stack);
  });
  installJava('com.android.okhttp.OkHttpClient','newCall',function(args,result,types,api){
    if(!args.length) return;
    const request=args[0],stack=javaStack();
    const url=typeof request.urlString==='function' ? request.urlString() : request.url();
    emit('url',String(url),api,{stage:'call_created',method:String(request.method())},stack);
    headers(request,api,stack);
  });
  installJava('okhttp3.Request$Builder','url',function(args,result,types,api){
    if(args.length) emit('url',String(args[0]),api,{stage:'constructed'},javaStack());
  });
  for(const method of ['header','addHeader']) installJava('okhttp3.Request$Builder',method,function(args,result,types,api){
    if(args.length===2 && sensitive.test(String(args[0]))) emit('header',String(args[1]),api,{name:String(args[0]),stage:'assigned'},javaStack());
  });
  installJava('javax.crypto.spec.SecretKeySpec','$init',function(args,result,types,api){
    if(types[0]!=='[B') return;
    const offset=args.length===4 ? Number(args[1]) : 0;
    const count=args.length===4 ? Number(args[2]) : args[0].length;
    emit('crypto_key',byteValue(args[0],offset,count),api,{encoding:'hex',algorithm:String(args[args.length-1]),stage:'key_object_constructed'},javaStack());
  });
  installJava('javax.crypto.KeyGenerator','generateKey',function(args,result,types,api){
    if(result) {
      const key=Java.cast(result,Java.use('java.security.Key'));
      const bytes=key.getEncoded();
      if(bytes===null) status('nonexportable_key',false,'Generated '+key.getAlgorithm()+' key has no exportable value');
      else emit('crypto_key',byteValue(bytes),api,{encoding:'hex',algorithm:String(key.getAlgorithm()),stage:'generated'},javaStack());
    }
  });
  installJava('java.security.spec.PKCS8EncodedKeySpec','$init',function(args,result,types,api){
    if(types[0]==='[B') emit('crypto_key',byteValue(args[0]),api,{encoding:'hex',format:'PKCS8',stage:'key_spec_constructed'},javaStack());
  });
  installJava('javax.crypto.Cipher','doFinal',function(args,result,types,api,returnType){
    // Primitive Java arrays are Frida proxies without $className. Use the
    // declared return type; checking result.$className would silently miss them.
    if(result && returnType==='[B') observeText('decoded_text',textBytes(result),api,{algorithm:String(this.getAlgorithm()),stage:'cipher_output'});
  });
  installJava('android.util.Base64','decode',function(args,result,types,api){
    observeText('decoded_text',textBytes(result),api,{stage:'base64_decoded'});
  });
}
function nativeStack(context) {
  try { return Thread.backtrace(context,Backtracer.ACCURATE).slice(0,20).map(address=>{
    const m=Process.findModuleByAddress(address),symbol=DebugSymbol.fromAddress(address);
    return {address:String(address),module:m ? m.name : '',offset:m ? String(address.sub(m.base)) : '',method:symbol.name || ''};
  }); } catch(_) {return [];}
}
function hookExport(module,name,callbacks) {
  const address=module.findExportByName(name);
  if(!address) return false;
  const key=String(address);
  if(hooked.has(key)) return true;
  try {hooks.push(Interceptor.attach(address,callbacks)); hooked.add(key);nativeHookCount++;status(module.name+'!'+name,true,'exported symbol; process_arch='+Process.arch);return true;}
  catch(e) {status(module.name+'!'+name,false,String(e));return false;}
}
function cstring(address) {
  try {
    if(address.isNull()) return '';
    // readCString(size) reads a fixed buffer in Frida; it is not a maximum
    // NUL-terminated length and can include unrelated memory after the string.
    // Find the terminator explicitly before decoding only the actual bytes.
    for(let length=0;length<4096;length++) {
      if(address.add(length).readU8()===0) return length ? address.readUtf8String(length) : '';
    }
    status('native_string_limit',false,'Omitted unterminated native string exceeding 4096 bytes');
  } catch(_) {}
  return '';
}
function observePayload(pointer,length,api,stack) {
  if(length<=0 || length>MAX_VALUE) {if(length>MAX_VALUE) status('payload_limit',false,api+': omitted '+length+' bytes');return;}
  try {const text=pointer.readUtf8String(length);if(text && !/[\x00-\x08\x0e-\x1f\uFFFD]/.test(text))
    observeText('transport_text',text,api,{stage:'tls_plaintext',bytes:length},stack);}catch(_){}
}
function installNative(module) {
  const moduleKey=module.name+'@'+module.base;
  if(nativeModules.has(moduleKey)) return;
  nativeModules.add(moduleKey);
  if(module.name==='libc.so') {
    hookExport(module,'getaddrinfo',{onEnter(args){this.host=cstring(args[0]);this.stack=nativeStack(this.context);},onLeave(ret){if(ret.toInt32()===0)emit('host',this.host,'libc.getaddrinfo',{stage:'dns_resolved'},this.stack);}});
    hookExport(module,'connect',{onEnter(args){
      try {const family=args[1].readU16(),port=(args[1].add(2).readU8()<<8)|args[1].add(3).readU8();
        if(family===2){let ip=[];for(let i=0;i<4;i++)ip.push(args[1].add(4+i).readU8());this.destination=ip.join('.')+':'+port;}
        else if(family===10){let ip=[];for(let i=0;i<16;i+=2)ip.push(((args[1].add(8+i).readU8()<<8)|args[1].add(9+i).readU8()).toString(16));this.destination='['+ip.join(':')+']:'+port;}
        this.stack=nativeStack(this.context);
      }catch(_){}
    },onLeave(ret){if(this.destination)emit('connection',this.destination,'libc.connect',{stage:'connect_attempt',return_code:ret.toInt32()},this.stack);}});
  }
  if(/ssl|cronet|flutter|boringssl/i.test(module.name)) {
    hookExport(module,'SSL_set_tlsext_host_name',{onEnter(args){emit('host',cstring(args[1]),module.name+'!SSL_set_tlsext_host_name',{stage:'tls_sni'},nativeStack(this.context));}});
    hookExport(module,'SSL_write',{onEnter(args){this.buffer=args[1];this.stack=nativeStack(this.context);},onLeave(ret){if(ret.toInt32()>0)observePayload(this.buffer,ret.toInt32(),module.name+'!SSL_write',this.stack);}});
    hookExport(module,'SSL_read',{onEnter(args){this.buffer=args[1];this.stack=nativeStack(this.context);},onLeave(ret){if(ret.toInt32()>0)observePayload(this.buffer,ret.toInt32(),module.name+'!SSL_read',this.stack);}});
  }
}
rpc.exports={stop(){stopping=true;return {events:emitted,hooks:hooked.size};}};
if(NATIVE_HOOKS_ENABLED) Process.enumerateModules().forEach(installNative);
let javaReady=false;
function attemptJava() {
  if(Java.available) Java.perform(()=>{if(!javaReady){javaReady=true;status('java_bridge',true,'Java runtime ready');}installJavaHooks();});
}
attemptJava();
function nativeCapabilities() {
  if(!NATIVE_HOOKS_ENABLED) {
    status('native_observer',false,'Disabled by capture option native_hooks=false; Java observation remains enabled. The Frida Java bridge still uses native internals.');
    return;
  }
  const modules=Process.enumerateModules();
  const translated=modules.some(m=>/libndk_translation|libhoudini/i.test(m.name));
  status('native_observer',nativeHookCount>0,'process_arch='+Process.arch+'; installed_symbols='+nativeHookCount+'; translated_arm_libraries='+translated+'; DNS/connect and exported TLS only. ARM translated code, stripped/inlined TLS, QUIC and HTTP/2 decoding are not covered.');
  status('flutter_native_module',modules.some(m=>m.name==='libflutter.so'),'Visible native libflutter module only; visibility does not establish full Dart/TLS coverage.');
}
const timer=setInterval(()=>{if(stopping){clearInterval(timer);return;}if(NATIVE_HOOKS_ENABLED)Process.enumerateModules().forEach(installNative);attemptJava();nativeCapabilities();},1500);
setTimeout(()=>{status('java_bridge',javaReady,javaReady?'available':'Java runtime unavailable');
  ['okhttp3.OkHttpClient.newCall','android.webkit.WebView.loadUrl','javax.crypto.spec.SecretKeySpec.$init'].forEach(key=>{if(!hooked.has(key))status(key,false,'class/method unavailable or not loaded');});},6000);
nativeCapabilities();
