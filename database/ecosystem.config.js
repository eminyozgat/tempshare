// PM2 Ecosystem Configuration
// Auto-restart için kullanılır
// Kullanım: pm2 start ecosystem.config.js
// Production deployment configuration

module.exports = {
    apps: [{
        name: 'tempshare',
        script: 'index.js',
        cwd: './database',
        instances: 1,
        exec_mode: 'fork',
        watch: false,
        max_memory_restart: '500M',
        env: {
            NODE_ENV: 'production',
            PORT: 3000
        },
        error_file: './logs/pm2-error.log',
        out_file: './logs/pm2-out.log',
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        merge_logs: true,
        autorestart: true,
        max_restarts: 10,
        min_uptime: '10s',
        restart_delay: 4000
    }]
};

