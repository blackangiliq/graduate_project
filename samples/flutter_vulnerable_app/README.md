# Pocket Shop (deliberately vulnerable Flutter app)

FOR TESTING THE ANALYZER ONLY. Never build, publish or deploy this app.

A small shop app (orders, wallet, help center, deep links) written with the mistakes that
static analysis of Flutter apps should find: in the Dart code, in the Android and iOS
configuration, in the CI workflow and web page, and in the dependencies.

- Lines marked `[Dxx]` (Dart), `[Mxx]` (mobile and build configuration) and `[Gxx]`
  (dependencies) are neutral markers. Their meaning is in `samples/flutter_ground_truth.json`.
  Some marked lines are safe on purpose.
- Lines that cannot hold a comment (XML attributes, `Info.plist` keys, `key.properties`,
  `.env`) are labelled through an `anchor` in the ground truth instead.
- `samples/flutter_safe_app` is the same app written securely; every finding there is a
  false positive.

All keys, passwords and tokens are fake: the AWS key is the documentation example, the
service-role token decodes to a sample payload with the signature "sample signature - not a
real key", and every server of the app is in the reserved `.example` domain.
