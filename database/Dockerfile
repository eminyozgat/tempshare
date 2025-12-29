# Node.js 20 LTS kullan
# Docker image for TempShare
FROM node:20-alpine

# Çalışma dizini
WORKDIR /app

# Database klasöründeki package dosyalarını kopyala
COPY database/package*.json ./

# Bağımlılıkları yükle
RUN npm ci --only=production

# Database klasöründeki tüm dosyaları kopyala
COPY database/ ./

# Public klasörünü kopyala (proje root'undan)
COPY public/ ./public/

# Port'u expose et
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/healthz', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Uygulamayı başlat
CMD ["node", "index.js"]

