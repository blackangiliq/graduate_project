import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';

/// Local copy of the customer's orders for offline browsing.
class OrderDatabase {
  Database? _db;

  Future<Database> get database async {
    return _db ??= await openDatabase(
      p.join(await getDatabasesPath(), 'orders.db'),
      version: 1,
      onCreate: (Database db, int version) => db.execute(
        'CREATE TABLE orders(id INTEGER PRIMARY KEY, title TEXT, status TEXT, total REAL)',
      ),
    );
  }

  Future<List<Map<String, Object?>>> search(String text) async {
    final db = await database;
    return db.rawQuery("SELECT * FROM orders WHERE title LIKE '%$text%'"); // [D14]
  }

  Future<Map<String, Object?>?> byId(int id) async {
    final db = await database;
    final rows = await db.rawQuery('SELECT * FROM orders WHERE id = ?', <Object?>[id]); // [D27]
    return rows.isEmpty ? null : rows.first;
  }

  Future<void> save(Map<String, Object?> order) async {
    final db = await database;
    await db.insert('orders', order, conflictAlgorithm: ConflictAlgorithm.replace);
  }
}
