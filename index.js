const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const crypto = require("crypto");
const querystring = require("querystring");
const cookieParser = require("cookie-parser");
const app = express();
const port = 3000;

require("dotenv").config();

app.use(express.static("public"));
app.use(bodyParser.json());
app.use(cookieParser());

const { SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, REDIRECT_URI } =
  process.env;
const shopTokens = {};

const verifyHmac = (query) => {
  const { hmac, ...rest } = query;
  const ordered = Object.keys(rest)
    .sort()
    .reduce((obj, key) => {
      obj[key] = rest[key];
      return obj;
    }, {});
  const message = querystring.stringify(ordered);
  const providedHmac = Buffer.from(hmac, "utf-8");
  const generatedHash = Buffer.from(
    crypto
      .createHmac("sha256", SHOPIFY_API_SECRET)
      .update(message)
      .digest("hex"),
    "utf-8"
  );

  try {
    return crypto.timingSafeEqual(generatedHash, providedHmac);
  } catch (e) {
    return false;
  }
};

app.get("/api/install", (req, res) => {
  const { botId } = req.query;

  if (!botId) {
    return res.status(400).send("Missing botId parameter.");
  }

  // Set a secure, httpOnly cookie with the botId
  res.cookie("pluggi_bot_id", botId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Secure in production
    sameSite: "lax",
    maxAge: 10 * 60 * 1000, // 10 minutes
  });

  // Redirect to the Shopify "App Store" / Install Link
  // Using the link from index.html as the mock App Store entry point
  const shopifyInstallUrl = "https://admin.shopify.com/?organization_id=198831934&no_redirect=true&redirect=/oauth/redirect_from_developer_dashboard?client_id%3Dd716db50e65f60d265dd47a861926306";
  
  res.redirect(shopifyInstallUrl);
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.get("/api", (req, res) => {
  const { shop, hmac } = req.query;

  if (!shop || !hmac) {
    return res.status(400).send("Missing shop or hmac parameter.");
  }

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC validation failed.");
  }

  if (shopTokens[shop]) {
    return res.redirect(`/app.html?shop=${shop}`);
  }

  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("shopify_auth_state", state, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });

  const authUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${REDIRECT_URI}&state=${state}`;

  res.redirect(authUrl);
});

app.get("/auth/callback", async (req, res) => {
  const { code, shop, hmac, state } = req.query;
  const stateCookie = req.cookies.shopify_auth_state;

  if (!code || !shop || !hmac || !state) {
    return res
      .status(400)
      .send("Missing code, shop, hmac, or state parameter.");
  }

  if (state !== stateCookie) {
    return res.status(403).send("Request origin cannot be verified.");
  }

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC validation failed.");
  }

  // Retrieve Bot ID from cookie
  const botId = req.cookies.pluggi_bot_id;
  if (!botId) {
      console.warn("Warning: No Bot ID found in cookie during callback.");
  }

  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code,
      }
    );

    const accessToken = response.data.access_token;
    shopTokens[shop] = accessToken;
    
    // Save integration logic (Mock)
    if (botId) {
        console.log(`SUCCESS: Integrated Bot ID [${botId}] with Shop [${shop}]`);
        console.log(`Access Token: ${accessToken}`);
    }

    res.clearCookie("shopify_auth_state");
    res.clearCookie("pluggi_bot_id"); // Clean up

    res.redirect(`/app.html?shop=${shop}&botId=${botId || 'unknown'}`);
  } catch (error) {
    console.error("Error exchanging code for access token:", error);
    res.status(500).send("Error exchanging code for access token.");
  }
});

app.post("/api/products", async (req, res) => {
  const { shop } = req.body;
  const accessToken = shopTokens[shop];

  if (!accessToken) {
    return res.status(401).send("Not authenticated.");
  }

  const query = `
    query {
      products(first: 10) {
        edges {
          node {
            id
            title
            description
            handle
            priceRangeV2 {
              minVariantPrice {
                amount
                currencyCode
              }
              maxVariantPrice {
                amount
                currencyCode
              }
            }
            images(first: 5) {
              edges {
                node {
                  id
                  url
                  altText
                  width
                  height
                }
              }
            }
            variants(first: 10) {
              edges {
                node {
                  id
                  title
                  price
                  sku
                  availableForSale
                }
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  `;
  const variables = {};

  try {
    const response = await axios.post(
      `https://${shop}/admin/api/2026-01/graphql.json`,
      {
        query,
        variables,
      },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": accessToken,
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error(
      "Error fetching products:",
      error.response ? error.response.data : error.message
    );
    const errorMessage =
      error.response && error.response.data && error.response.data.errors
        ? JSON.stringify(error.response.data.errors)
        : "Error fetching products.";
    res.status(500).send(errorMessage);
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
