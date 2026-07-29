FROM node:20-alpine AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
# Defaults stay empty for auth identity so accidental production builds do not
# bake the Compose e2e bearer token. infra/docker-compose.yml passes mock values.
ARG VITE_API_BASE_URL=http://localhost:8000/api/v1
ARG VITE_SOCKET_URL=http://localhost:8000
ARG VITE_DEV_AUTH_TOKEN=
ARG VITE_AUTH_SUBJECT=
ARG VITE_APPROVER_DISPLAY=
ARG VITE_EVENT_CHAT_ENABLED=true
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_SOCKET_URL=$VITE_SOCKET_URL \
    VITE_DEV_AUTH_TOKEN=$VITE_DEV_AUTH_TOKEN \
    VITE_AUTH_SUBJECT=$VITE_AUTH_SUBJECT \
    VITE_APPROVER_DISPLAY=$VITE_APPROVER_DISPLAY \
    VITE_EVENT_CHAT_ENABLED=$VITE_EVENT_CHAT_ENABLED
RUN pnpm build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
