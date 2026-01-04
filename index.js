const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const app = express();
const port = 3000;

require("dotenv").config();

app.use(express.static("public"));
app.use(bodyParser.json());

const { SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, REDIRECT_URI } =
  process.env;
const shopTokens = {};

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.post("/auth", (req, res) => {
  const { shop } = req.body;
  if (!shop) {
    return res.status(400).send("Missing shop parameter.");
  }
  const authUrl = `https://${shop}.myshopify.com/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${REDIRECT_URI}&state=nonce123`;
  res.json({ redirectUrl: authUrl });
});

app.get("/auth/callback", async (req, res) => {
  const { code, shop } = req.query;

  if (!code || !shop) {
    return res.status(400).send("Missing code or shop parameter.");
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

    res.redirect(`/app.html?shop=${shop}`);
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
