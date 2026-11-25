import 'dart:io';

import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Exports and restores the customer's receipts and wallet backup.
class BackupService {
  /// Restores a backup archive picked by the customer. Entries whose path would leave the
  /// backup folder are skipped.
  Future<int> restore(List<int> zipBytes) async {
    final documents = await getApplicationDocumentsDirectory();
    final target = p.join(documents.path, 'backup');
    final archive = ZipDecoder().decodeBytes(zipBytes);
    var restored = 0;
    for (final entry in archive) {
      final outPath = p.normalize(p.join(target, entry.name));
      if (!entry.isFile || !p.isWithin(target, outPath)) {
        continue;
      }
      final outFile = File(outPath);
      await outFile.create(recursive: true);
      await outFile.writeAsBytes(entry.content);
      restored++;
    }
    return restored;
  }

  /// Copies the receipts into the app's own files folder, which the FileProvider shares
  /// with the app that the customer picks in the share sheet.
  Future<String> exportReceipts(List<File> receipts) async {
    final support = await getApplicationSupportDirectory();
    final exportDir = Directory(p.join(support.path, 'receipts'));
    await exportDir.create(recursive: true);
    for (final receipt in receipts) {
      await receipt.copy(p.join(exportDir.path, p.basename(receipt.path)));
    }
    return exportDir.path;
  }

  /// Desktop build: packs the receipts folder into one archive, without a shell.
  Future<void> packForDesktop(String folder, String archiveName) async {
    await Process.run('tar', <String>['-czf', archiveName, '-C', folder, '.']);
  }
}
