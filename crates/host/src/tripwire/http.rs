//! `http_get`: the scheme and the host against the allowed domains.

use super::*;

impl Tripwire {
    pub(super) fn validate_url(
        &self,
        intent: &ProposedIntent,
    ) -> Result<ValidatedIntent, TripwireError> {
        let url_str = intent
            .params_url()
            .ok_or(TripwireError::MissingParam("url"))?;
        let url = url_str
            .parse::<url::Url>()
            .map_err(|_| TripwireError::InvalidUrl(url_str.to_string()))?;
        if self.require_https && url.scheme() != "https" {
            return Err(TripwireError::HttpsRequired(url_str.to_string()));
        }
        let host = url
            .host_str()
            .ok_or(TripwireError::InvalidUrl(url_str.to_string()))?;
        let allowed = self
            .allowed_domains
            .iter()
            .any(|d| host == d.as_str() || host.ends_with(&format!(".{d}")));
        if !allowed {
            return Err(TripwireError::DomainNotAllowed(host.to_string()));
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }
}
