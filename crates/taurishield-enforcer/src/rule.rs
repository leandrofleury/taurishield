use taurishield_core::Manifest;

use crate::EvaluationReport;

pub trait Rule: Send + Sync {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport);
}
