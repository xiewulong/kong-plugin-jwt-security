local aes = require "resty.aes"
local str = require "resty.string"
local jwt_parser = require "kong.plugins.jwt.jwt_parser"

local _M = {
  PRIORITY = 10,
  VERSION = "0.1.0",
}

local sign = {
  MD5 = function(data) return ndk.set_var.set_md5(data) end,
  SHA1 = function(data) return ndk.set_var.set_sha1(data) end,
}

function _M:access(config)
  kong.log.debug("access")

  local matches, err = ngx.re.match(kong.request.get_header(config.header_name), "^\\s*bearer\\s+(\\S+)\\s*$", "i")
  if err or (not matches) or #matches < 1 then
    local err = "Can not match token"
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Token: ", matches[1])

  local jwt, err = jwt_parser:new(matches[1])
  if err then
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end

  -- TODO: 一次性JWT
  -- local jwt_id = jwt.claims[config.jwt_id_claim_name]
  -- if not jwt_id or jwt_id == "" then
  --   local err = "No '" .. config.jwt_id_claim_name .. "' in claims"
  --   kong.log.err(err)
  --   kong.response.exit(401, { message = err })
  -- end
  -- kong.log.debug("JWT id: ", jwt_csa)

  local request_body = kong.request.get_raw_body()
  kong.log.debug("Request body: ", request_body);
  if not request_body or request_body == "" then
    return
  end

  local jwt_csa = jwt.claims[config.content_signature_algorithm_claim_name]
  if not jwt_csa or not sign[string.upper(jwt_csa)] then
    local err = "Invalid '" .. config.content_signature_algorithm_claim_name .. "' in claims"
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end
  jwt_csa = string.upper(jwt_csa)
  kong.log.debug("Content signature algorithm: ", jwt_csa)

  local jwt_csn = jwt.claims[config.content_signature_claim_name]
  if not jwt_csn or jwt_csn == "" then
    local err = "Invalid '" .. config.content_signature_claim_name .. "' in claims"
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Content signature: ", jwt_csn)

  local csn = sign[jwt_csa](request_body)
  kong.log.debug("Request body ", jwt_csa, ": ", csn)
  if csn ~= jwt_csn then
    local err = "Invalid content signature"
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end

  -- TODO: 通过Consumer获取对称加密的Key和IV

  local aes_256_cbc_with_iv, err = aes:new("a123456789012345678901234567890b", nil, aes.cipher(256, "cbc"), { iv = "1516239022000000" })
  if err then
    kong.log.err(err)
    kong.response.exit(401, { message = err })
  end
  kong.ctx.aes_256_cbc_with_iv = aes_256_cbc_with_iv

  local err = "Invalid content"

  local success, encrypted_request_body = pcall(ndk.set_var.set_decode_hex, request_body)
  if not success then
    kong.response.exit(400, { message = err })
  end

  local data = kong.ctx.aes_256_cbc_with_iv:decrypt(encrypted_request_body)
  if not data then
    kong.log.err(err)
    kong.response.exit(400, { message = err })
  end
  kong.log.debug(data)
  kong.service.request.set_raw_body(data)
end

function _M:body_filter(config)
  kong.log.debug("body_filter")

  -- ngx.ctx.response_body = (ngx.ctx.buffered or "") .. ngx.arg[1]

  -- if ngx.arg[2] then
  --   ngx.arg[1] = ndk.set_var.set_encode_hex(kong.ctx.aes_256_cbc_with_iv:encrypt(ngx.ctx.response_body))
  -- else
  --   ngx.arg[1] = nil
  -- end
end

return _M
