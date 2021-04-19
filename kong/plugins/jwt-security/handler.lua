local jwt_parser = require "kong.plugins.jwt.jwt_parser"
local aes = require "resty.aes"
local str = require "resty.string"

local encoder = {
  BASE64 = function(data) return ngx.encode_base64(data) end,
  HEX = function(data) return ndk.set_var.set_encode_hex(data) end,
}

local decoder = {
  BASE64 = function(data) local r = ngx.decode_base64(data) return r, r end,
  HEX = function(data) return pcall(ndk.set_var.set_decode_hex, data) end,
}

local signer = {
  MD5 = function(data) return ndk.set_var.set_md5(data) end,
  SHA1 = function(data) return ndk.set_var.set_sha1(data) end,
}

local _M = {
  PRIORITY = 10,
  VERSION = "0.1.0",
}

function _M:access(config)
  kong.log.debug("access")

  -- 获取JWT Token
  if not kong.ctx.shared.authenticated_jwt_token then
    local err = "Invalid token"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Token: ", kong.ctx.shared.authenticated_jwt_token)

  -- 解析JWT Token
  local jwt, err = jwt_parser:new(kong.ctx.shared.authenticated_jwt_token)
  if err then
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end

  -- TODO: 一次性JWT Token验证
  -- local jwt_id = jwt.claims[config.jwt_id_claim_name]
  -- if not jwt_id or jwt_id == "" then
  --   local err = "No '" .. config.jwt_id_claim_name .. "' in claims"
  --   kong.log.debug(err)
  --   kong.response.exit(401, { message = err })
  -- end
  -- kong.log.debug("JWT id: ", jwt_csa)

  -- 获取Request body
  local request_body = kong.request.get_raw_body()
  if not request_body or request_body == "" then
    local err = "Invalid content"
    kong.log.debug(err)
    kong.response.exit(400, { message = err })
  end
  kong.log.debug("Request body: ", request_body)

  -- 获取签名算法
  local jwt_csa = string.upper(jwt.claims[config.content_signature_algorithm_claim_name] or "md5")
  if not signer[jwt_csa] then
    local err = "Invalid '" .. config.content_signature_algorithm_claim_name .. "' in claims"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Content signature algorithm: ", jwt_csa)

  -- 获取签名
  local jwt_csn = jwt.claims[config.content_signature_claim_name]
  if not jwt_csn or jwt_csn == "" then
    local err = "Invalid '" .. config.content_signature_claim_name .. "' in claims"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Content signature: ", jwt_csn)

  -- 验证签名
  local csn = signer[jwt_csa](request_body)
  kong.log.debug("Request body ", jwt_csa, ": ", csn)
  if csn ~= jwt_csn then
    local err = "Invalid content signature"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end

  -- 未开启消息体加密则跳过
  if not config.content_encrypt_enabled then
    kong.log.debug('Content encrypt disabled')
    return
  end
  kong.log.debug('Content encrypt enabled')

  -- 获取客户端凭证
  local credential = kong.client.get_credential()
  if not credential then
    local err = "No credentials found"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Credential secret: ", credential.secret)

  -- 获取密钥盐
  local key_salt = jwt.claims[config.key_salt_claim_name]
  kong.log.debug("Key salt: ", key_salt)

  -- 获取加密实例
  local cryptor, err = aes:new(credential.secret, key_salt, nil, aes.hash.sha1)
  if err then
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end

  local err = "Invalid content"

  -- 获取编码方案
  local jwt_ces = string.upper(jwt.claims[config.content_encoding_scheme_claim_name] or "base64")
  if not decoder[jwt_ces] then
    local err = "Invalid '" .. config.content_encoding_scheme_claim_name .. "' in claims"
    kong.log.debug(err)
    kong.response.exit(401, { message = err })
  end
  kong.log.debug("Content encoding scheme: ", jwt_ces)

  -- 获取解码后的请求体
  local success, encrypted_request_body = decoder[jwt_ces](request_body)
  if not success then
    kong.log.debug(err)
    kong.response.exit(400, { message = err })
  end

  -- 获取解密后的请求体
  local decrypted_request_body = cryptor:decrypt(encrypted_request_body)
  if not decrypted_request_body then
    kong.log.debug(err)
    kong.response.exit(400, { message = err })
  end

  -- 设置上游请求体
  kong.log.debug("Decrypted request body: ", decrypted_request_body)
  kong.service.request.set_raw_body(decrypted_request_body)

  -- 设置本次请求生命周期内需要用到的资源
  kong.ctx.plugin.cryptor = cryptor
  kong.ctx.plugin.encoding_scheme = jwt_ces
  kong.ctx.plugin.encrypt_response_body = true
end

function _M:header_filter(config)
  kong.log.debug("header_filter")

  if kong.ctx.plugin.encrypt_response_body then
    ngx.header.Content_Length = nil   -- 删除内容长度
    ngx.header.Content_Encrypted = true   -- 设置内容加密标识
  end

end

function _M:body_filter(config)
  kong.log.debug("body_filter")

  -- 非响应体加密跳过
  if not kong.ctx.plugin.encrypt_response_body then
    return
  end

  -- 组装响应体
  kong.ctx.plugin.response_body = (kong.ctx.plugin.response_body or "") .. ngx.arg[1]

  if ngx.arg[2] then
    kong.log.debug("Response body: ", kong.ctx.plugin.response_body)
    local encrypted_response_body = encoder[kong.ctx.plugin.encoding_scheme](kong.ctx.plugin.cryptor:encrypt(kong.ctx.plugin.response_body))  -- 加密响应体
    kong.log.debug("Encrypted response body: ", encrypted_response_body)

    -- 设置加密响应体
    ngx.arg[1] = encrypted_response_body
  else
    -- 清除已组装的块
    ngx.arg[1] = nil
  end
end

return _M
