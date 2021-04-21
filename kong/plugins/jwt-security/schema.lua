local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-security",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { content_encoding_scheme_claim_name = { type = "string", default = "ces" }, },
          { content_encrypt_enabled = { type = "boolean", required = true, default = true }, },
          { content_signature_algorithm_claim_name = { type = "string", default = "csa" }, },
          { content_signature_claim_name = { type = "string", default = "csn" }, },
          { iv_claim_name = { type = "string", default = "ivx" }, },
          -- { jwt_id_claim_name = { type = "string", default = "jti" }, },
          { key_salt_claim_name = { type = "string", default = "kst" }, },
          -- { no_replay = { type = "boolean", default = false }, },
        },
      },
    },
  },
}
