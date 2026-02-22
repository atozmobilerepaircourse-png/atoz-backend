FROM node:18

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all source code
COPY . .

# Cloud Run uses port 8080
ENV PORT=8080
EXPOSE 8080

# Start the app
CMD ["npm", "start"]
