use crate::schema::{Response, Assertion, Issuer, Status, StatusCode, Subject, AuthnStatement, AuthnContext, AttributeStatement, SubjectConfirmation, SubjectConfirmationData, Conditions, AuthnContextClassRef, AudienceRestriction, SubjectNameID};
use chrono::{Utc};
use crate::signature::{Signature, SignedInfo, SignatureValue, CanonicalizationMethod, SignatureMethod, Reference, DigestMethod, DigestValue, Transform, Transforms};
use crate::key_info::{KeyInfo, X509Data};
use crate::attribute::{Attribute, AttributeValue};

use crate::crypto;
use super::sp_extractor::RequiredAttribute;
use crate::idp::ResponseParams;

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


fn build_assertion(params: &ResponseParams)
    -> Assertion
{
    let ResponseParams {
        idp_x509_cert_der: _,
        subject_name_id,
        audience,
        acs_url,
        issuer,
        in_response_to_id,
        attributes,
        not_before,
        not_on_or_after
    } = *params;


    let assertion_id = crypto::gen_saml_assertion_id();

    let attribute_statements = if attributes.is_empty() {
        None
    } else {
        Some(vec![
            AttributeStatement {
                attributes: build_attributes(attributes)
            }
        ])
    };

    Assertion {
        id: assertion_id.clone(),
        issue_instant: Utc::now(),
        version: "2.0".to_string(),
        issuer: Issuer {
            value: Some(issuer.to_string()),
            ..Default::default()
        },
        signature: None,
        subject: Some(Subject {
            name_id: Some(SubjectNameID {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                value: subject_name_id.to_string(),
            }),
            subject_confirmations: Some(vec![SubjectConfirmation {
                method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before,
                    not_on_or_after,
                    recipient: Some(acs_url.to_owned()),
                    in_response_to: Some(in_response_to_id.to_string()),
                    address: None,
                    content: None
                })
            }]),
        }),
        conditions: Some(build_conditions(audience)),
        authn_statements: Some(vec![ build_authn_statement("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified")]),
        attribute_statements,
    }

}

fn build_response(params: &ResponseParams) -> Response
{
    let issuer = Issuer {
        value: Some(params.issuer.to_string()),
        ..Default::default()
    };

    let response_id = crypto::gen_saml_response_id();

    Response {
        id: response_id.clone(),
        in_response_to: Some(params.in_response_to_id.to_owned()),
        version: "2.0".to_string(),
        issue_instant: Utc::now(),
        destination: Some(params.acs_url.to_string()),
        consent: None,
        issuer: Some(issuer),
        signature: Some(signature_template(&response_id, params.idp_x509_cert_der)),
        status: Status {
            status_code: StatusCode {
                value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string())
            },
            status_message: None,
            status_detail: None
        },
        encrypted_assertion: None,
        assertion: Some(build_assertion(params)),
    }
}

pub fn build_response_template(params: &ResponseParams) -> Response
{
    build_response(params)
}