import express, { Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import cors from 'cors';

// Initialize the Express app
const app = express();

// Middleware to parse JSON requests
app.use(express.json());

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', 'views'); // Place your EJS files in a 'views' directory

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Serve static assets (if needed for styles, images, etc.)
app.use(express.static('public'));

app.use(cors({
  origin: 'http://localhost:4200',
  optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}));

// Basic route
app.get('/', (req: Request, res: Response) => {
  res.send('Hello, world!');
});


// OIDC configuration data
const oidcConfiguration = {
  issuer: 'http://localhost:3000', // Your OIDC issuer URL
  authorization_endpoint: 'http://localhost:3000/auth', // Authorization endpoint
  token_endpoint: 'http://localhost:3000/token', // Token endpoint
  end_session_endpoint: 'http://localhost:3000/logout', // Logout endpoint
  response_types_supported: ['code'],
  subject_types_supported: ['public', 'pairwise'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: ['openid', 'offline_access'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
  claims_supported: ['sub', 'name', 'email'],
};

// OIDC configuration endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json(oidcConfiguration);
});

// Token expiration times in seconds
const ACCESS_TOKEN_EXPIRATION = 2 * 60; // 2 min
const REFRESH_TOKEN_EXPIRATION = 60 * 60 * 24 * 7; // 7 days
const ID_TOKEN_EXPIRATION = 60 * 60; // 1h

// Mock
const revokedTokens = new Set();

// Example function to revoke a token
function revokeToken(token: any) {
  revokedTokens.add(token);
}

// Example middleware to check if a token is revoked
function isTokenRevoked(token: any) {
  return revokedTokens.has(token);
}

app.get('/auth', (req: Request, res: Response) => {
  const { scope, redirect_uri, response_type, client_id, state, code_challenge, code_challenge_method } = req.query;

  // Ensure required query parameters are present
  if (!scope || !redirect_uri || !response_type || !client_id || !state || !code_challenge || !code_challenge_method) {
    res.status(400).send('Missing required query parameters');
    return;
  }

  // Render the login page with query parameters
  res.render('login', {
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  });
});

app.post('/auth', (req: Request, res: Response) => {
  const { username, password, client_id, redirect_uri, state, code_challenge } = req.body;

  // Generate a random authorization code
  const authorizationCode = randomBytes(16).toString('hex');

  // Redirect back to the redirect_uri with the authorization code and state
  const redirectTo = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
  res.redirect(redirectTo);
});

// /token route handler for both authorization code and refresh token grants
app.post('/token', (req: Request, res: Response) => {
  const { grant_type } = req.body;

  // Authorization Code Grant
  if (grant_type === 'authorization_code') {
    const { code, client_id, code_verifier } = req.body;

    // Mock validation (ensure real-world validation in production)
    if (!client_id || !code) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    // Generate Access Token (JWT)
    const accessToken = jwt.sign(
      { sub: client_id, scope: 'read write' },
      'ACCESS_TOKEN_SECRET',
      { expiresIn: ACCESS_TOKEN_EXPIRATION }
    );

    // Generate Refresh Token (JWT)
    const refreshToken = jwt.sign(
      { sub: client_id },
      'REFRESH_TOKEN_SECRET',
      { expiresIn: REFRESH_TOKEN_EXPIRATION }
    );

    // Generate ID Token (JWT)
    const idToken = jwt.sign({
      sub: 'test-user-id', // Unique identifier for the user (e.g., user ID)
      name: 'John Doe', // User's name
      email: 'john@doe.com', // User's email address
      iat: Math.floor(Date.now() / 1000), // Issued at time
      aud: client_id, // Audience, typically your application's client ID
      iss: 'http://localhost:3000/', // Issuer identifier
    }, 'ID_TOKEN_SECRET', { expiresIn: ID_TOKEN_EXPIRATION });

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_EXPIRATION,
    });
    return;
  }

  // Refresh Token Grant
  else if (grant_type === 'refresh_token') {
    const { refresh_token, client_id } = req.body;

    if (!refresh_token || !client_id) {
      res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token or client_id' });
      return;
    }

    // Verify the refresh token
    try {
      const payload = jwt.verify(refresh_token, 'REFRESH_TOKEN_SECRET') as JwtPayload;

      // Ensure the refresh token matches the expected client
      if (payload.sub !== client_id) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Client ID mismatch' });
        return;
      }

      // Generate a new Access Token
      const newAccessToken = jwt.sign(
        { sub: client_id, scope: 'read write' },
        'ACCESS_TOKEN_SECRET',
        { expiresIn: ACCESS_TOKEN_EXPIRATION }
      );

      // Generate a new Refresh Token (rotating token)
      const newRefreshToken = jwt.sign(
        { sub: client_id },
        'REFRESH_TOKEN_SECRET',
        { expiresIn: REFRESH_TOKEN_EXPIRATION }
      );

      // Respond with the new token pair
      res.json({
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_EXPIRATION,
      });
      return;
    } catch (error) {
      res.status(401).json({ error: 'invalid_grant', error_description: 'Refresh token is invalid or expired' });
      return;
    }
  } else {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }
});

// Logout endpoint
app.get('/logout', (req: Request, res: Response) => {
  const { id_token_hint, post_logout_redirect_uri } = req.query;

  res.redirect(post_logout_redirect_uri as string);
});

// Start the server
app.listen(3000, () => {
  console.log(`Server is running at http://localhost:3000`);
});