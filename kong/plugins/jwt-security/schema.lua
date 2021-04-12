local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-security",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { content_encoding_scheme_claim_name = { type = "string", required = true, default = "ces" }, },
          { content_encrypt_enabled = { type = "boolean", required = true, default = true }, },
          { content_signature_algorithm_claim_name = { type = "string", required = true, default = "csa" }, },
          { content_signature_claim_name = { type = "string", required = true, default = "csn" }, },
          -- { jwt_id_claim_name = { type = "string", required = true, default = "jti" }, },
          { key_salt_claim_name = { type = "string", required = true, default = "kst" }, },
          -- { no_replay = { type = "boolean", required = true, default = false }, },
        },
      },
    },
  },
}
