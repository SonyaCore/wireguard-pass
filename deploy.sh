#!/bin/bash

# Railway deployment script for WireGuard PaaS

echo "🚀 Deploying WireGuard PaaS to Railway..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Please install it first:"
    echo "npm install -g @railway/cli"
    exit 1
fi

# Login to Railway (if not already logged in)
echo "🔐 Checking Railway authentication..."
if ! railway whoami &> /dev/null; then
    echo "Please login to Railway:"
    railway login
fi

# Initialize Railway project
echo "🏗️ Initializing Railway project..."
railway init wireguard-paas

# Set environment variables
echo "🔧 Setting environment variables..."
railway variables set SECRET_KEY=$(openssl rand -hex 32)
railway variables set SERVER_ENDPOINT=your-app-name.railway.app:51820
railway variables set PORT=8080

# Deploy the application
echo "📦 Deploying application..."
railway up --detach

# Get the deployment URL
echo "🌍 Getting deployment URL..."
RAILWAY_URL=$(railway status --json | jq -r '.deployments[0].url')

echo "✅ Deployment complete!"
echo "🔗 Your WireGuard PaaS is available at: $RAILWAY_URL"
echo ""
echo "⚠️  Important next steps:"
echo "1. Update SERVER_ENDPOINT with your Railway domain:"
echo "   railway variables set SERVER_ENDPOINT=${RAILWAY_URL#https://}:51820"
echo ""
echo "2. Test the API:"
echo "   curl $RAILWAY_URL/api/status"
echo ""
echo "3. Register your first user:"
echo "   curl -X POST $RAILWAY_URL/api/register \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"username\":\"admin\",\"email\":\"admin@example.com\",\"password\":\"password123\"}'"
