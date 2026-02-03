const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';
const JWT_EXPIRES_IN = '7d';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// OAuth Configuration
const OAUTH_CONFIG = {
    discord: {
        clientId: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        authorizeUrl: 'https://discord.com/api/oauth2/authorize',
        tokenUrl: 'https://discord.com/api/oauth2/token',
        userUrl: 'https://discord.com/api/users/@me',
        scopes: 'identify'
    },
    github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        authorizeUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        userUrl: 'https://api.github.com/user',
        scopes: 'read:user'
    },
    google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
        scopes: 'openid profile'
    }
};

// Initialize Turso database client
const db = createClient({
    url: process.env.TURSO_DATABASE_URL || 'file:local.db',
    authToken: process.env.TURSO_AUTH_TOKEN
});

// Initialize database tables
async function initDatabase() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            oauth_provider TEXT,
            oauth_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_data TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// Redirect root to todo-app.html
app.get('/', (req, res) => {
    res.redirect('/todo-app.html');
});

// Auth middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Helper: Find or create OAuth user
async function findOrCreateOAuthUser(provider, oauthId, username) {
    // Check if user exists with this OAuth
    const existing = await db.execute({
        sql: 'SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?',
        args: [provider, oauthId]
    });

    if (existing.rows.length > 0) {
        return existing.rows[0];
    }

    // Create unique username if needed
    let finalUsername = username;
    let counter = 1;
    while (true) {
        const check = await db.execute({
            sql: 'SELECT id FROM users WHERE username = ?',
            args: [finalUsername]
        });
        if (check.rows.length === 0) break;
        finalUsername = `${username}${counter}`;
        counter++;
    }

    // Create new user
    const result = await db.execute({
        sql: 'INSERT INTO users (username, oauth_provider, oauth_id) VALUES (?, ?, ?)',
        args: [finalUsername, provider, oauthId]
    });

    return {
        id: Number(result.lastInsertRowid),
        username: finalUsername,
        oauth_provider: provider,
        oauth_id: oauthId
    };
}

// OAuth: Start authorization
app.get('/api/oauth/:provider', (req, res) => {
    const { provider } = req.params;
    const config = OAUTH_CONFIG[provider];

    if (!config || !config.clientId) {
        return res.status(400).json({ error: `OAuth provider ${provider} not configured` });
    }

    const redirectUri = `${BASE_URL}/api/oauth/${provider}/callback`;
    const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: config.scopes
    });

    // Google requires additional params
    if (provider === 'google') {
        params.append('access_type', 'offline');
        params.append('prompt', 'consent');
    }

    res.redirect(`${config.authorizeUrl}?${params.toString()}`);
});

// OAuth: Handle callback
app.get('/api/oauth/:provider/callback', async (req, res) => {
    const { provider } = req.params;
    const { code, error } = req.query;
    const config = OAUTH_CONFIG[provider];

    if (error || !code) {
        return res.redirect(`/todo-app.html?auth_error=${encodeURIComponent(error || 'No code received')}`);
    }

    if (!config || !config.clientId) {
        return res.redirect('/todo-app.html?auth_error=Provider+not+configured');
    }

    try {
        const redirectUri = `${BASE_URL}/api/oauth/${provider}/callback`;

        // Exchange code for token
        const tokenParams = new URLSearchParams({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code: code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
        });

        const tokenRes = await fetch(config.tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: tokenParams.toString()
        });

        const tokenData = await tokenRes.json();

        if (!tokenData.access_token) {
            console.error('Token error:', tokenData);
            return res.redirect('/todo-app.html?auth_error=Failed+to+get+token');
        }

        // Get user info
        const userRes = await fetch(config.userUrl, {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
                'Accept': 'application/json',
                'User-Agent': 'TodoListApp'
            }
        });

        const userData = await userRes.json();

        // Extract user info based on provider
        let oauthId, username;
        if (provider === 'discord') {
            oauthId = userData.id;
            username = userData.username;
        } else if (provider === 'github') {
            oauthId = String(userData.id);
            username = userData.login;
        } else if (provider === 'google') {
            oauthId = userData.id;
            username = userData.name?.replace(/\s+/g, '') || userData.email?.split('@')[0] || 'user';
        }

        if (!oauthId) {
            console.error('User data error:', userData);
            return res.redirect('/todo-app.html?auth_error=Failed+to+get+user+info');
        }

        // Find or create user
        const user = await findOrCreateOAuthUser(provider, oauthId, username);

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        // Redirect with token
        res.redirect(`/todo-app.html?auth_token=${token}&auth_user=${encodeURIComponent(JSON.stringify({ id: user.id, username: user.username }))}`);

    } catch (err) {
        console.error('OAuth error:', err);
        res.redirect('/todo-app.html?auth_error=Authentication+failed');
    }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({ error: 'Username must be 3-30 characters' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check if username exists
        const existingUser = await db.execute({
            sql: 'SELECT id FROM users WHERE username = ?',
            args: [username]
        });

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Username already taken' });
        }

        // Hash password and create user
        const passwordHash = bcrypt.hashSync(password, 10);
        const result = await db.execute({
            sql: 'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            args: [username, passwordHash]
        });

        const userId = Number(result.lastInsertRowid);

        // Generate token
        const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: userId, username }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Find user
        const result = await db.execute({
            sql: 'SELECT * FROM users WHERE username = ?',
            args: [username]
        });

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = result.rows[0];

        // Check if this is an OAuth-only user
        if (!user.password_hash) {
            return res.status(401).json({ error: 'This account uses OAuth login. Please sign in with ' + user.oauth_provider });
        }

        // Check password
        if (!bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Generate token
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get tasks endpoint
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const result = await db.execute({
            sql: 'SELECT task_data, updated_at FROM tasks WHERE user_id = ?',
            args: [req.user.id]
        });

        if (result.rows.length === 0) {
            return res.json({ tasks: [], schoolCategories: [], ui: {}, updatedAt: null });
        }

        const taskRecord = result.rows[0];
        const data = JSON.parse(taskRecord.task_data);
        res.json({
            ...data,
            updatedAt: taskRecord.updated_at
        });
    } catch (err) {
        console.error('Get tasks error:', err);
        res.json({ tasks: [], schoolCategories: [], ui: {}, updatedAt: null });
    }
});

// Save tasks endpoint
app.post('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const { tasks, schoolCategories, ui } = req.body;
        const taskData = JSON.stringify({ tasks, schoolCategories, ui });

        // Check if record exists
        const existing = await db.execute({
            sql: 'SELECT id FROM tasks WHERE user_id = ?',
            args: [req.user.id]
        });

        if (existing.rows.length > 0) {
            await db.execute({
                sql: 'UPDATE tasks SET task_data = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
                args: [taskData, req.user.id]
            });
        } else {
            await db.execute({
                sql: 'INSERT INTO tasks (user_id, task_data) VALUES (?, ?)',
                args: [req.user.id, taskData]
            });
        }

        res.json({ message: 'Tasks saved successfully', updatedAt: new Date().toISOString() });
    } catch (err) {
        console.error('Save tasks error:', err);
        res.status(500).json({ error: 'Failed to save tasks' });
    }
});

// Verify token endpoint
app.get('/api/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Voice task parsing endpoint (existing functionality)
app.post('/api/parse-task', async (req, res) => {
    try {
        const { text, section, category, today } = req.body || {};
        if (!text || typeof text !== 'string') {
            return res.status(400).send('Missing text.');
        }

        const apiKey = process.env.OPENAI_API_KEY;
        if (!apiKey) {
            return res.status(500).send('Missing OPENAI_API_KEY.');
        }

        const systemPrompt = [
            'You convert a spoken task into structured JSON for a todo app.',
            'Rules:',
            '- Always return valid JSON that matches the schema exactly.',
            '- Use YYYY-MM-DD for date. If no date is given, use today.',
            '- If a date is given without a year, assume the current year based on "today".',
            '- Priority is 1-5. Map phrases like "low/pretty low" => 2, "medium" => 3, "high/urgent" => 5.',
            '- If recurrence is not specified, use "none".',
            '- Keep tags short (0-4).',
            '- Notes should include any extra details not in the title.',
            `Today is ${today || 'unknown'}.`
        ].join('\n');

        const userPrompt = [
            `Section: ${section || 'general'}`,
            `Category: ${category || 'none'}`,
            `User said: ${text}`
        ].join('\n');

        const response = await fetch('https://api.openai.com/v1/responses', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                input: [
                    {
                        role: 'system',
                        content: [{ type: 'input_text', text: systemPrompt }]
                    },
                    {
                        role: 'user',
                        content: [{ type: 'input_text', text: userPrompt }]
                    }
                ],
                text: {
                    format: {
                        type: 'json_schema',
                        json_schema: {
                            name: 'todo_task',
                            strict: true,
                            schema: {
                                type: 'object',
                                additionalProperties: false,
                                properties: {
                                    name: { type: 'string' },
                                    date: { type: 'string' },
                                    priority: { type: 'integer', minimum: 1, maximum: 5 },
                                    tags: { type: 'array', items: { type: 'string' } },
                                    notes: { type: 'string' },
                                    recurrence: {
                                        type: 'string',
                                        enum: ['none', 'daily', 'weekly', 'monthly']
                                    }
                                },
                                required: ['name', 'date', 'priority', 'tags', 'notes', 'recurrence']
                            }
                        }
                    }
                }
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            return res.status(response.status).send(errorText || 'OpenAI request failed.');
        }

        const data = await response.json();
        const outputText = extractOutputText(data);
        const parsed = JSON.parse(outputText);

        return res.json(parsed);
    } catch (err) {
        return res.status(500).send(err.message || 'Server error.');
    }
});

function extractOutputText(data) {
    if (data && typeof data.output_text === 'string') {
        return data.output_text;
    }
    const parts = [];
    for (const item of data.output || []) {
        if (item.type === 'message') {
            for (const content of item.content || []) {
                if (content.type === 'output_text') {
                    parts.push(content.text);
                }
            }
        }
    }
    return parts.join('');
}

// Start server after database is initialized
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`TodoListApp server started on port ${PORT}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
