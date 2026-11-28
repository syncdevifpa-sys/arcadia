/* Autoriza somente a conta dedicada, no ambiente de teste. */
const router = require('express').Router();
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { authenticateToken, authorizeAdmin } = require('../middlewares/auth.middleware');
const db = require('../config/database');
const cookie = 'arcadia_drive_oauth';
const callbackPath = '/api/google-drive/callback';
const account = 'portalarcadia.contato@gmail.com';

const { config } = require('../services/document-drive.service');

router.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Referrer-Policy', 'no-referrer');
    next();
});

router.post('/authorize', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const settings = config();
        if (!settings || new URL(settings.uri).host !== req.get('host'))
            return res.status(503).json({ error: 'Abra pelo mesmo domínio cadastrado em GOOGLE_DRIVE_REDIRECT_URI.' });
        try {
            await db.execute('SELECT id FROM google_drive_conexao WHERE id = ?', [1]);
        } catch {
            return res.status(503).json({ error: 'Falha ao consultar a tabela do Drive no Neon de teste. Confira a conexão e a migração 003.' });
        }
        const nonce = crypto.randomBytes(32).toString('base64url');
        const verifier = crypto.randomBytes(48).toString('base64url');
        const state = jwt.sign({ nonce, verifier }, settings.key, { expiresIn: '10m', audience: 'arcadia-drive' });
        res.cookie(cookie, state, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600000, path: callbackPath });
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.search = new URLSearchParams({
            client_id: settings.clientId, redirect_uri: settings.uri, response_type: 'code',
            scope: 'openid email https://www.googleapis.com/auth/drive.file', login_hint: account,
            access_type: 'offline', prompt: 'consent', state: nonce, code_challenge_method: 'S256',
            code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url')
        });
        res.json({ url: url.href });
    } catch (error) {
        res.status(503).json({ error: error.setup || 'A configuração do Google Drive está incompleta.' });
    }
});

router.get('/callback', async (req, res) => {
    let stage = 'session';
    const signed = (req.headers.cookie || '').split(';').map(value => value.trim())
        .find(value => value.startsWith(cookie + '='))?.slice(cookie.length + 1);
    res.clearCookie(cookie, { httpOnly: true, secure: true, sameSite: 'lax', path: callbackPath });
    try {
        const settings = config();
        if (!settings || new URL(settings.uri).host !== req.get('host')) return res.sendStatus(404);
        const state = jwt.verify(signed, settings.key, { algorithms: ['HS256'], audience: 'arcadia-drive' });
        if (req.query.error) stage = 'consent';
        if (req.query.state !== state.nonce || typeof req.query.code !== 'string') throw Error();
        stage = 'token';
        const response = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST', signal: AbortSignal.timeout(10000),
            body: new URLSearchParams({
                code: req.query.code, client_id: settings.clientId, client_secret: settings.secret,
                redirect_uri: settings.uri, grant_type: 'authorization_code', code_verifier: state.verifier
            })
        });
        if (!response.ok) throw Error();
        const token = await response.json();
        stage = 'profile';
        const profile = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: 'Bearer ' + token.access_token }, signal: AbortSignal.timeout(10000)
        });
        if (!profile.ok) throw Error();
        stage = 'account';
        const identity = await profile.json();
        if (identity.email !== account || identity.email_verified !== true || !token.refresh_token ||
            !String(token.scope).split(' ').includes('https://www.googleapis.com/auth/drive.file')) throw Error();
        stage = 'save';
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', settings.key, iv);
        const encrypted = Buffer.concat([cipher.update(token.refresh_token, 'utf8'), cipher.final()]);
        const credential = [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64url')).join('.');
        await db.execute(
            'INSERT INTO google_drive_conexao (id, credencial) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET credencial = EXCLUDED.credencial',
            [credential]
        );
        res.redirect(303, '/admin.html?drive=connected');
    } catch {
        console.warn('Google Drive: falha na etapa ' + stage);
        res.redirect(303, '/admin.html?drive=' + stage);
    }
});
/* Ensaio isolado de armazenamento, usando apenas conteúdo fictício. */
router.post('/test', authenticateToken, authorizeAdmin, async (req, res) => {
    let stage = 'configuração';
    try {
        const settings = config();
        if (new URL(settings.uri).host !== req.get('host'))
            return res.status(503).json({ error: 'Abra o endereço fixo do Preview do Drive.' });

        stage = 'leitura da autorização';
        const [[connection]] = await db.execute('SELECT credencial FROM google_drive_conexao WHERE id = ?', [1]);
        if (!connection) return res.status(409).json({ error: 'Autorize a conta dedicada antes do teste.' });
        const [iv, tag, encrypted] = connection.credencial.split('.').map(part => Buffer.from(part, 'base64url'));
        const decipher = crypto.createDecipheriv('aes-256-gcm', settings.key, iv);
        decipher.setAuthTag(tag);
        const refreshToken = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');

        stage = 'renovação do acesso';
        const access = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST', signal: AbortSignal.timeout(8000),
            body: new URLSearchParams({
                client_id: settings.clientId, client_secret: settings.secret,
                refresh_token: refreshToken, grant_type: 'refresh_token'
            })
        });
        if (!access.ok) throw Error();
        const token = (await access.json()).access_token;
        if (!token) throw Error();
        async function drive(path, options = {}) {
            const response = await fetch('https://www.googleapis.com/' + path, {
                ...options, signal: AbortSignal.timeout(8000),
                headers: { ...options.headers, Authorization: 'Bearer ' + token }
            });
            if (!response.ok) throw Error();
            return response;
        }

        stage = 'criação da pasta';
        const folder = await (await drive('drive/v3/files?fields=id', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'Arcádia - teste ' + new Date().toISOString(), mimeType: 'application/vnd.google-apps.folder' })
        })).json();

        stage = 'envio do arquivo';
        const content = 'Arquivo fictício de teste do Arcádia. ' + crypto.randomUUID();
        const boundary = 'arcadia-' + crypto.randomUUID();
        const metadata = JSON.stringify({ name: 'arcadia-teste.txt', mimeType: 'text/plain', parents: [folder.id] });
        const body = [
            '--' + boundary, 'Content-Type: application/json; charset=UTF-8', '', metadata,
            '--' + boundary, 'Content-Type: text/plain; charset=UTF-8', '', content,
            '--' + boundary + '--', ''
        ].join('\r\n');
        const file = await (await drive('upload/drive/v3/files?uploadType=multipart&fields=id', {
            method: 'POST', headers: { 'Content-Type': 'multipart/related; boundary=' + boundary }, body
        })).json();

        stage = 'download e conferência do conteúdo';
        const download = await drive('drive/v3/files/' + encodeURIComponent(file.id) + '?alt=media');
        if (await download.text() !== content) throw Error();

        stage = 'verificação das permissões';
        for (const id of [folder.id, file.id]) {
            const result = await (await drive('drive/v3/files/' + encodeURIComponent(id) +
                '/permissions?fields=nextPageToken,permissions(role,type)')).json();
            if (result.nextPageToken || !result.permissions?.length ||
                result.permissions.some(permission => permission.role !== 'owner')) throw Error();
        }
        res.json({ message: 'Pasta criada. Envio e download conferidos. A pasta e o arquivo estão acessíveis apenas à conta proprietária.' });
    } catch {
        console.warn('Google Drive: teste falhou na etapa de ' + stage);
        res.status(502).json({ error: 'O teste falhou na etapa de ' + stage + '. Uma pasta criada durante o teste pode ter ficado no Drive.' });
    }
});

module.exports = router;
