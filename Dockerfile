FROM kong:latest

ENV KONG_LUA_PACKAGE_PATH "/usr/local/?.lua;;"
ENV KONG_PLUGINS "bundled, jwt-security"

ADD ./kong/plugins/jwt-security /usr/local/kong/plugins/jwt-security
