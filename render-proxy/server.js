require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const helmet = require('helmet');
const { URL } = require('url');

const app = express();
app.use(helmet());

const PORT = process.env.PORT || 10000;
const API_KEY = process.env.PROXY_API_KEY;
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '').split(',').map(s=>s.trim());
const ALLOW_CORS = (process.env.ALLOW_CORS === 'true');

app.get('/', (req,res)=>res.send('Proxy running'));

// Proxy endpoint
app.get('/r', async (req,res)=>{
    const key = req.query.api_key;
    if(key !== API_KEY) return res.status(401).send('Unauthorized');

    const target = req.query.url;
    if(!target) return res.status(400).send('Missing url param');

    let targetUrl;
    try { targetUrl = new URL(target); } 
    catch(e){ return res.status(400).send('Invalid URL'); }

    if(ALLOWED_HOSTS.length && !ALLOWED_HOSTS.includes(targetUrl.hostname))
        return res.status(403).send('Target host not allowed');

    if(ALLOW_CORS){
        res.set('Access-Control-Allow-Origin','*');
        res.set('Access-Control-Allow-Methods','GET,POST,OPTIONS');
        res.set('Access-Control-Allow-Headers','Content-Type,X-API-Key');
    }

    try{
        const upstream = await fetch(target);
        const contentType = upstream.headers.get('content-type')||'';
        if(contentType.includes('text/html')){
            const body = await upstream.text();
            const $ = cheerio.load(body);
            ['a','img','script','link','iframe','form'].forEach(tag=>{
                ['href','src','action'].forEach(attr=>{
                    $(tag).each((i,el)=>{
                        const cur = $(el).attr(attr);
                        if(!cur) return;
                        if(cur.startsWith('data:')||cur.startsWith('javascript:')) return;
                        let abs;
                        try { abs = new URL(cur,targetUrl).toString(); } catch(e){ return; }
                        const prox = `/r?url=${encodeURIComponent(abs)}&api_key=${API_KEY}`;
                        $(el).attr(attr,prox);
                    });
                });
            });
            res.set('content-type','text/html; charset=utf-8');
            return res.send($.html());
        } else {
            res.set('content-type',contentType);
            upstream.body.pipe(res);
        }
    }catch(e){
        console.error(e);
        res.status(502).send('Error fetching target');
    }
});

// CORS preflight
app.options('/r', (req, res) => {
    if (ALLOW_CORS){
        res.set('Access-Control-Allow-Origin','*');
        res.set('Access-Control-Allow-Methods','GET,POST,OPTIONS');
        res.set('Access-Control-Allow-Headers','Content-Type,X-API-Key');
    }
    res.sendStatus(204);
});

app.listen(PORT,()=>console.log(`Proxy running on port ${PORT}`));
