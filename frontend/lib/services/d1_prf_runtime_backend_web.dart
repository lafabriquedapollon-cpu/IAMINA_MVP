// B2b.2 isolated candidate, not composed into main or legacy host.
import 'dart:convert';
import '../core/domain/glucose_quantity_evidence.dart';
import 'd1_runtime_admission.dart';
import 'd1_prf_possession_web.dart';

final class D1WebPrfRuntimeBackend implements D1DurableRuntimeBackend {
  final D1WebPrfAcquirer _acquirer;
  const D1WebPrfRuntimeBackend(this._acquirer);

  @override
  Future<D1DurableRuntimeLease> acquire(D1RuntimeAcquisition acquisition) async {
    final identity = acquisition.identity;
    final possession = acquisition.takePrfPossession();
    final lease = await _acquirer.openBoundLease(possession,
        owner: identity.owner, epoch: identity.epoch,
        generation: identity.generation, acquisitionId: acquisition.acquisitionId,
        isPending: () => acquisition.isPending,
        isSessionCurrent: () => acquisition.isSessionCurrent);
    if (!acquisition.isPending) {
      await lease.retire();
      throw const D1RuntimeAdmissionException();
    }
    return _RuntimeLease(identity, acquisition.acquisitionId, lease);
  }
}

final class _RuntimeLease implements D1DurableRuntimeLease {
  @override
  final D1RuntimeIdentity identity;
  @override
  final String acquisitionId;
  final D1WebPrfLease _lease;
  _RuntimeLease(this.identity, this.acquisitionId, this._lease);

  @override
  Future<bool> verifyCurrent() => _lease.verifyCurrent();

  @override
  Future<GlucoseQuantityEvidence?> readEvidence(String uuid) async {
    final data = jsonDecode(await _lease.readEvidence(uuid));
    if (data == null) return null;
    if (data is! Map<String,dynamic> || data.length != 4 ||
        data['uuid'] != uuid || data['provenance'] != 'userEntered' ||
        data['originalValue'] is! num || data['unit'] is! String) {
      throw const D1RuntimeAdmissionException();
    }
    final unit = GlucoseSourceUnit.fromExplicitUcumCode(data['unit'] as String);
    if (unit == null) throw const D1RuntimeAdmissionException();
    return GlucoseQuantityEvidence.userEntry(
        originalValue: (data['originalValue'] as num).toDouble(), declaredUnit: unit);
  }

  @override
  Future<void> retire() => _lease.retire();
}
