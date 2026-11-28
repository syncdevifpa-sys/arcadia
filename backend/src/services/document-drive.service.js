/* Armazenamento privado para os novos documentos do Preview do Drive. */
const crypto = require('node:crypto');
const db = require('../config/database');
const callbackPath = '/api/google-drive/callback';

function config() {
    if (process.env.VERCEL_ENV !== 'preview') throw Object.assign(Error(), { setup: 'O Drive de teste exige um deploy Preview.' });
    if (process.env.DB_CLIENT !== 'postgres') throw Object.assign(Error(), { setup: 'Defina DB_CLIENT=postgres neste Preview.' });
    const database = new URL(process.env.POSTGRES_URL);
    const testHost = 'ep-floral-resonance-bbs5f7ew.c-15.us-east-1.aws.neon.tech';
    const pooledTestHost = testHost.replace('.', '-pooler.');
    if (![testHost, pooledTestHost].includes(database.hostname) || database.pathname !== '/arcadiabd') throw Object.assign(Error(), { setup: 'POSTGRES_URL deve apontar para o banco arcadiabd do Neon de teste.' });
    const { GOOGLE_CLIENT_ID: clientId, GOOGLE_CLIENT_SECRET: secret, GOOGLE_DRIVE_REDIRECT_URI: uri,
        GOOGLE_DRIVE_ENCRYPTION_KEY: rawKey } = process.env;
    if (!clientId || !secret) throw Object.assign(Error(), { setup: 'O Preview precisa de GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET.' });
    if (!/^[a-f0-9]{64}$/i.test(rawKey || '')) throw Object.assign(Error(), { setup: 'GOOGLE_DRIVE_ENCRYPTION_KEY deve ter 64 caracteres hexadecimais.' });
    if (!uri || !URL.canParse(uri)) throw Object.assign(Error(), { setup: 'GOOGLE_DRIVE_REDIRECT_URI está ausente ou inválida.' });
    const url = new URL(uri);
    if (url.protocol !== 'https:' || url.pathname !== callbackPath || url.search || url.hash ||
        url.hostname === 'portalarcadia.vercel.app') throw Object.assign(Error(), { setup: 'Use a URI HTTPS de retorno do Preview em GOOGLE_DRIVE_REDIRECT_URI.' });
    return { clientId, secret, uri, key: Buffer.from(rawKey, 'hex') };
}

function enabled() {
    return process.env.VERCEL_ENV === 'preview' &&
        process.env.VERCEL_GIT_COMMIT_REF === 'test/google-drive';
}

async function connect() {
    const settings = config();
    const [[connection]] = await db.execute('SELECT credencial FROM google_drive_conexao WHERE id = ?', [1]);
    if (!connection) throw Error('Conta do Drive não autorizada.');
    const [iv, tag, ciphertext] = connection.credencial.split('.').map(part => Buffer.from(part, 'base64url'));
    const decipher = crypto.createDecipheriv('aes-256-gcm', settings.key, iv);
    decipher.setAuthTag(tag);
    const refresh = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST', signal: AbortSignal.timeout(8000),
        body: new URLSearchParams({
            client_id: settings.clientId, client_secret: settings.secret,
            refresh_token: refresh, grant_type: 'refresh_token'
        })
    });
    if (!response.ok) throw Error('Não foi possível renovar a autorização do Drive.');
    const token = (await response.json()).access_token;
    if (!token) throw Error('O Drive não retornou um token de acesso.');
    return async function request(path, options = {}) {
        const result = await fetch('https://www.googleapis.com/' + path, {
            ...options, signal: AbortSignal.timeout(12000),
            headers: { ...options.headers, Authorization: 'Bearer ' + token }
        });
        if (!result.ok) throw Error('O Google Drive não concluiu a operação.');
        return result;
    };
}

async function publicationsFolder(request) {
    const name = 'Publicações do Arcadia';
    const mimeType = 'application/vnd.google-apps.folder';
    const query = new URLSearchParams({
        q: "trashed = false and 'root' in parents and mimeType = '" + mimeType + "' and name = '" + name + "'",
        fields: 'nextPageToken,files(id)'
    });
    const { files, nextPageToken } = await (await request('drive/v3/files?' + query)).json();
    if (nextPageToken || files.length > 1) throw Error('Há mais de uma pasta Publicações do Arcadia acessível.');
    const folder = files[0] || await (await request('drive/v3/files?fields=id', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, mimeType })
    })).json();
    if (!folder.id) throw Error('O Drive não retornou a pasta de publicações.');
    const permissions = await (await request('drive/v3/files/' + encodeURIComponent(folder.id) +
        '/permissions?fields=nextPageToken,permissions(role)')).json();
    if (permissions.nextPageToken || !permissions.permissions?.length ||
        permissions.permissions.some(permission => permission.role !== 'owner'))
        throw Error('A pasta de publicações precisa ser privada.');
    return folder.id;
}

async function upload(content, mime) {
    const request = await connect();
    const boundary = 'arcadia-' + crypto.randomUUID();
    const folderId = await publicationsFolder(request);
    const metadata = JSON.stringify({ name: 'arcadia-documento-' + crypto.randomUUID(), mimeType: mime, parents: [folderId] });
    const header = '--' + boundary + '\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n' +
        metadata + '\r\n--' + boundary + '\r\nContent-Type: ' + mime + '\r\n\r\n';
    const body = Buffer.concat([Buffer.from(header), content, Buffer.from('\r\n--' + boundary + '--\r\n')]);
    const remote = await (await request('upload/drive/v3/files?uploadType=multipart&fields=id', {
        method: 'POST', headers: { 'Content-Type': 'multipart/related; boundary=' + boundary }, body
    })).json();
    if (!remote.id) throw Error('O Drive não retornou o identificador do arquivo.');
    try {
        const permissions = await (await request('drive/v3/files/' + encodeURIComponent(remote.id) +
            '/permissions?fields=nextPageToken,permissions(role)')).json();
        if (permissions.nextPageToken || !permissions.permissions?.length ||
            permissions.permissions.some(permission => permission.role !== 'owner'))
            throw Error('O arquivo do Drive não está privado.');
        return remote.id;
    } catch (error) {
        await trash(remote.id, request).catch(() => console.warn('Drive: falha ao limpar upload de teste.'));
        throw error;
    }
}

async function download(id) {
    const request = await connect();
    const response = await request('drive/v3/files/' + encodeURIComponent(id) + '?alt=media');
    return Buffer.from(await response.arrayBuffer());
}

async function trash(id, request) {
    request = request || await connect();
    await request('drive/v3/files/' + encodeURIComponent(id), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trashed: true })
    });
}

module.exports = { config, enabled, upload, download, trash };