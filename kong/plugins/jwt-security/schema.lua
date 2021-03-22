local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-security",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { content_signature_claim_name = { type = "string", required = true, default = "csn" }, },
          { content_signature_algorithm_claim_name = { type = "string", required = true, default = "csa" }, },
          { header_name = { type = "string", required = true, default = "authorization" }, },
          { jwt_id_claim_name = { type = "string", required = true, default = "jti" }, },
        },
      },
    },
  },
}
