import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import Stripe from "stripe";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access" });
  }
  const secret = process.env.JWT_SECRET_TOKEN;
  try {
    jwt.verify(token, secret);
    next();
  } catch (error) {
    return res.status(401).send({ error: true, message: "Invalid token" });
  }
};

const sendResponse = (res, status, data) => {
  res.status(status).send(data);
};

const errorHandler = (err, req, res, next) => {
  console.error(err.message);
  sendResponse(res, 500, { error: true, message: "Internal Server Error" });
};

async function run() {
  const db = client.db(process.env.MONGODB_DB);
  const userCollection = db.collection("users");
  const productCollection = db.collection("products");
  const categoryCollection = db.collection("categories");
  const reviewCollection = db.collection("reviews");
  const orderCollection = db.collection("orders");

  app.get("/", (_req, res) => {
    sendResponse(res, 200, { message: "Vue server is running!" });
  });

  app.post("/api/payment", async (req, res) => {
    const { products, name, email } = req.body;

    const customer = await stripe.customers.create({
      email,
      name,
    });

    const items = products.map((product) => ({
      price_data: {
        currency: "usd",
        product_data: {
          images: [product.thumbnail],
          name: product.title,
        },
        unit_amount: Math.round(parseFloat(product.price) * 100),
      },
      quantity: product.quantity,
    }));

    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: items,
        mode: "payment",
        customer: customer.id,
        success_url: `${req.headers.origin}/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${req.headers.origin}/cancel`,
      });

      if (!session) {
        return res.status(400).json({ error: "Session not created" });
      }
      else {
        const order = {
          user: name,
          email,
          products,
          total: products.reduce(
            (acc, product) => acc + product.price * product.quantity,
            0
          ),
          status: "pending",
          createdAt: new Date(),
        };
        await orderCollection.insertOne(order); 
      }

      sendResponse(res, 200, { id: session.id });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/payment", async (req, res) => {
    const { id } = req.query;
    if (!id) {
      return res.status(400).json({ error: "Missing session ID" });
    }
    try {
      const session = await stripe.checkout.sessions.retrieve(id, {
        expand: ["line_items", "customer_details", "payment_intent"],
      });

      sendResponse(res, 200, session);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/orders", async (req, res) => {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Missing email" });
    }
    
    try {
      const orders = await orderCollection.find({ email }).toArray();
      sendResponse(res, 200, orders);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/token", async (req, res) => {
    const data = req.body;
    const user = await userCollection.findOne({ email: data.email });
    if (!user) {
      return sendResponse(res, 400, {
        error: true,
        message: "User does not exist",
      });
    }
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    const JWToken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWToken);
    sendResponse(res, 200, { token });
  });

  app.post("/api/auth/signup", async (req, res) => {
    try {
      const { name, email, password } = req.body;
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return sendResponse(res, 400, {
          error: true,
          message: "User already exists",
        });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, email, password: hashedPassword };
      const createUser = await userCollection.insertOne(user);
      if (!createUser) {
        return sendResponse(res, 400, {
          error: true,
          message: "User not created",
        });
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      sendResponse(res, 201, { token });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/signin", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return sendResponse(res, 400, {
          error: true,
          message: "User does not exist",
        });
      }
      const isPasswordCorrect = await bcrypt.compare(password, user?.password);
      if (!isPasswordCorrect) {
        return sendResponse(res, 400, {
          error: true,
          message: "Password is incorrect",
        });
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      sendResponse(res, 200, { token });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/users", authMiddleware, async (_req, res) => {
    try {
      const users = await userCollection.find().toArray();
      sendResponse(res, 200, users);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const user = req.body;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: user }
      );
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await userCollection.deleteOne({
        _id: new ObjectId(id),
      });
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products", async (req, res) => {
    try {
      const { search, category, price, rating, skip, limit, sort, sortBy } = req.query;
  
      let query = {};
  
      if (search) {
        query.$or = [
          { title: { $regex: search, $options: "i" } },
          { description: { $regex: search, $options: "i" } },
        ];
      }
  
      if (category) {
        query.category = category;
      }
  
      if (price) {
        const priceLimit = parseInt(price);
        query.price = { $lte: priceLimit };
      }
  
      if (rating) {
        const ratingValue = parseInt(rating);
        query.rating = { $gte: ratingValue };
      }
  
      const totalProducts = await productCollection.countDocuments(query);
      let cursor = productCollection.find(query);
  
      cursor = cursor.skip(parseInt(skip)).limit(parseInt(limit));
  
      if (sortBy && sort) {
        const sortDirection = sort === "asc" ? 1 : -1;
        const sortFields = { [sortBy]: sortDirection };
        cursor = cursor.sort(sortFields);
      }
  
      const products = await cursor.toArray();
  
      sendResponse(res, 200, { products, totalProducts });
    } catch (error) {
      console.error(error);
      sendResponse(res, 500, { message: "Internal Server Error" });
    }
  });
  

  app.get("/api/products/random", async (req, res) => {
    try {
      const products = await productCollection
        .aggregate([{ $sample: { size: 10 } }])
        .toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const product = await productCollection.findOne({
        _id: new ObjectId(id),
      });
      sendResponse(res, 200, product);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products/:user", async (req, res) => {
    try {
      const { user } = req.params;
      const products = await productCollection.find({ user }).toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/products", authMiddleware, async (req, res) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const product = req.body;
      product.user = email;
      product.createdAt = new Date();
      const result = await productCollection.insertOne(product);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/products/:id", authMiddleware, async (req, res) => {
    try {
      const product = req.body;
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const findProduct = await productCollection.findOne({
        _id: new ObjectId(id),
      });
      if (findProduct?.email !== email) {
        return sendResponse(res, 403, {
          error: true,
          message: "Unauthorized access",
        });
      }
      const result = await productCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: product }
      );
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/products/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const product = await productCollection.findOne({
        _id: new ObjectId(id),
      });
      if (product?.user !== email) {
        return sendResponse(res, 403, {
          error: true,
          message: "Unauthorized access",
        });
      }
      const result = await productCollection.deleteOne({
        _id: new ObjectId(id),
      });
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/categories", async (req, res) => {
    try {
      const categories = await categoryCollection.find().toArray();
      sendResponse(res, 200, categories);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/categories/:category", async (req, res) => {
    try {
      const { category } = req.params;
      const products = await productCollection.find({ category }).toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/reviews/:productId", async (req, res) => {
    try {
      const { productId } = req.params;
      const result = await reviewCollection.find({ productId }).toArray();
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/reviews/:productId", authMiddleware, async (req, res) => {
    try {
      const { productId } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { name, email } = decodedToken;
      const data = req.body;
      data.productId = productId;
      data.name = name;
      data.email = email;
      data.createdAt = new Date();
      const result = await reviewCollection.insertOne(data);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/orders", authMiddleware, async (req, res) => {
    try {
      const { user } = req.query;
      const orders = await orderCollection.find({ user }).toArray();
      sendResponse(res, 200, orders);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/orders", authMiddleware, async (req, res) => {
    try {
      const data = req.body;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return sendResponse(res, 404, {
          error: true,
          message: "User not found",
        });
      }
      data.user = email;
      data.createdAt = new Date();
      const result = await orderCollection.insertOne(data);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.use(errorHandler);
}

run().catch(console.dir);

const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Vue server listening on port ${port}`);
});
