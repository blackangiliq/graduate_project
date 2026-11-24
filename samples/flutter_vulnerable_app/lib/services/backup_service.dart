import 'dart:io';

import 'package:archive/archive.dart';
import 'package:path_provider/path_provider.dart';

/// Exports and restores the customer's receipts and wallet backup.
class BackupService {
  /// Restores a backup archive picked by the customer.
  Future<int> restore(List<int> zipBytes) async {
    final target = await getApplicationDocumentsDirectory();
    final archive = ZipDecoder().decodeBytes(zipBytes);
    var restored = 0;
    for (final file in archive) {
      if (!file.isFile) {
        continue;
      }
      final outFile = File('${target.path}/${file.name}'); // [D20]
      await outFile.create(recursive: true);
      await outFile.writeAsBytes(file.content as List<int>);
      restored++;
    }
    return restored;
  }

  /// Copies the receipts to shared storage so that other apps can open them.
  Future<String> exportReceipts(List<File> receipts) async {
    final dir = await getExternalStorageDirectory(); // [D22]
    final exportDir = Directory('${dir!.path}/PocketShop/receipts');
    await exportDir.create(recursive: true);
    for (final receipt in receipts) {
      await receipt.copy('${exportDir.path}/${receipt.uri.pathSegments.last}');
    }
    return exportDir.path;
  }

  /// Desktop build: packs the receipts folder into one archive.
  Future<void> packForDesktop(String folder, String archiveName) async {
    await Process.run('sh', ['-c', 'tar -czf $archiveName -C $folder .']); // [D19]
  }
}
