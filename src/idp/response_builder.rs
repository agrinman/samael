use crate::schema::{Response, Assertion, Issuer, Status, StatusCode, Subject, AuthnStatement, AuthnContext, AttributeStatement, SubjectConfirmation, SubjectConfirmationData, Conditions, AuthnContextClassRef, AudienceRestriction, SubjectNameID};
use chrono::{Utc};
use crate::signature::{Signature, SignedInfo, SignatureValue, CanonicalizationMethod, SignatureMethod, Reference, DigestMethod, DigestValue, Transform, Transforms};
use crate::key_info::{KeyInfo, X509Data};
use crate::attribute::{Attribute, AttributeValue};

use crate::crypto;
use super::sp_extractor::RequiredAttribute;

fn signature_template(ref_id: &str, x509_cert_der: &[u8]) -> Signature {
    Signature {
        id: None,
        signed_info: SignedInfo {
            id: None,
            canonicalization_method: CanonicalizationMethod {
                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string()
            },
            signature_method: SignatureMethod {
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string(), hmac_output_length: None
            },
            reference: vec![
                Reference {
                    transforms: Some(Transforms {
                        transforms: vec![Transform {
                            algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string(),
                            xpath: None,
                        }, Transform {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                            xpath: None,
                        }]
                    }),
                    digest_method: DigestMethod { algorithm: "http://www.w3.org/2000/09/xmldsig#sha1".to_string() },
                    digest_value: DigestValue { base64_content: "".to_string() },
                    uri: Some(format!("#{}", ref_id)),
                    reference_type: None,
                    id: None
                }
            ]
        },
        signature_value: SignatureValue { id: None, base64_content: "".to_string() },
        key_info: Some(vec![KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificate: Some(crypto::mime_encode_x509_cert(x509_cert_der))
            })
        }]),
    }
}

fn build_conditions(audience: &str) -> Conditions {
    Conditions {
        not_before: None,
        not_on_or_after: None,
        audience_restrictions: Some(vec![AudienceRestriction {
            audience: vec![audience.to_string()]
        }]),
        one_time_use: None,
        proxy_restriction: None
    }
}

fn build_authn_statement(class: &str) -> AuthnStatement {
    AuthnStatement {
        authn_instant: Some(Utc::now()),
        session_index: None,
        session_not_on_or_after: None,
        subject_locality: None,
        authn_context: Some(AuthnContext {
            value: Some(AuthnContextClassRef {
                value: Some(class.to_string())
            })
        })
    }
}

pub struct ResponseAttribute<'a> {
    pub required_attribute: RequiredAttribute,
    pub value: &'a str,
}

fn build_attributes(formats_names_values: &[ResponseAttribute]) -> Vec<Attribute> {
    formats_names_values.iter().map(|attr| {
        Attribute {
            friendly_name: None,
            name: Some(attr.required_attribute.name.clone()),
            name_format: attr.required_attribute.format.clone(),
            values: vec![AttributeValue {
                attribute_type: Some("xs:string".to_string()),
                value: Some(attr.value.to_string())
            }]
        }
    }).collect()
}


fn build_assertion(name_id: &str, request_id: &str, issuer: Issuer, recipient: &str, audience: &str, attributes: &[ResponseAttribute])
    -> Assertion
{
    let assertion_id = crypto::gen_saml_assertion_id();

    Assertion {
        id: assertion_id.clone(),
        issue_instant: Utc::now(),
        version: "2.0".to_string(),
        issuer,
        signature: None,
        subject: Some(Subject {
            name_id: Some(SubjectNameID {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                value: name_id.to_owned(),
            }),
            subject_confirmations: Some(vec![SubjectConfirmation {
                method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before: None,
                    not_on_or_after: None,
                    recipient: Some(recipient.to_owned()),
                    in_response_to: Some(request_id.to_owned()),
                    address: None,
                    content: None
                })
            }]),
        }),
        conditions: Some(build_conditions(audience)),
        authn_statements: Some(vec![ build_authn_statement("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified")]),
        attribute_statements: Some(vec![
            AttributeStatement {
                attributes: build_attributes(attributes)
            }
        ]),
    }

}

fn build_response(name_id: &str,
                  issuer: &str,
                  request_id: &str,
                  attributes: &[ResponseAttribute],
                  destination: &str,
                  audience: &str,
                  x509_cert: &[u8]) -> Response
{
    let issuer = Issuer {
        value: Some(issuer.to_string()),
        ..Default::default()
    };

    let response_id = crypto::gen_saml_response_id();

    Response {
        id: response_id.clone(),
        in_response_to: Some(request_id.to_owned()),
        version: "2.0".to_string(),
        issue_instant: Utc::now(),
        destination: Some(destination.to_string()),
        consent: None,
        issuer: Some(issuer.clone()),
        signature: Some(signature_template(&response_id, x509_cert)),
        status: Status {
            status_code: StatusCode {
                value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string())
            },
            status_message: None,
            status_detail: None
        },
        encrypted_assertion: None,
        assertion: Some(build_assertion(name_id, request_id, issuer, destination, audience, attributes)),
    }
}

pub fn build_response_template(cert_der: &[u8],
                               name_id: &str,
                               audience: &str,
                               issuer: &str,
                               acs_url: &str,
                               request_id: &str,
                               attributes: &[ResponseAttribute]) -> Response
{
    build_response(name_id, issuer, request_id, attributes, acs_url, audience, cert_der)
}