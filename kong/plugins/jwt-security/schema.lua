local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-security",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    -- { config = {
    --     type = "",
    --   },
    -- },
  },
}
