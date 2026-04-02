import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import fs from 'fs/promises';
import path from 'path';

interface Product {
  name: string;
  description: string;
  [key: string]: any;
}

interface ErrorWithParent extends Error {
  parent: Error;
}

interface StorageOptions {
  useDatabase: boolean;
  databaseConfig?: {
    database: string;
    username: string;
    password: string;
    dialect: 'mysql' | 'postgres' | 'sqlite' | 'mariadb' | 'mssql';
  };
  filePath?: string;
}

const storageOptions: StorageOptions = {
  useDatabase: true,
  databaseConfig: {
    database: 'database',
    username: 'username',
    password: 'password',
    dialect: 'mysql',
  },
  filePath: path.join(__dirname, 'products.json'),
};

const models = storageOptions.useDatabase && storageOptions.databaseConfig ? {
  sequelize: new Sequelize(
    storageOptions.databaseConfig.database,
    storageOptions.databaseConfig.username,
    storageOptions.databaseConfig.password,
    { dialect: storageOptions.databaseConfig.dialect }
  ),
} : null;

async function getProductsFromDatabase(criteria: string): Promise<Product[]> {
  if (!models) throw new Error('Database models not initialized');
  const query = `
    SELECT * FROM Products 
    WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
    ORDER BY name
  `;
  return await models.sequelize.query(query, {
    replacements: { criteria: `%${criteria}%` },
    type: QueryTypes.SELECT,
  });
}

async function getProductsFromFile(criteria: string): Promise<Product[]> {
  const data = await fs.readFile(storageOptions.filePath!, 'utf8');
  const products: Product[] = JSON.parse(data);
  return products.filter(product =>
    (product.name.includes(criteria) || product.description.includes(criteria))
  );
}

async function getProducts(criteria: string): Promise<Product[]> {
  if (storageOptions.useDatabase) {
    return await getProductsFromDatabase(criteria);
  } else {
    return await getProductsFromFile(criteria);
  }
}

function getProductsSyncFromFile(criteria: string): Product[] {
  const data = require('fs').readFileSync(storageOptions.filePath!, 'utf8');
  const products: Product[] = JSON.parse(data);
  return products.filter(product =>
    (product.name.includes(criteria) || product.description.includes(criteria))
  );
}

function getProductsSync(criteria: string): Product[] {
  if (storageOptions.useDatabase) {
    throw new Error('Synchronous operation is not supported for database retrieval');
  } else {
    return getProductsSyncFromFile(criteria);
  }
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sessionId: string = req.sessionID || 'default';
      let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string ?? '');
      criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

      const products: Product[] = await getProducts(criteria);

      products.forEach(product => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });

      req.session[sessionId] = { products }; // Save products in the session

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
};