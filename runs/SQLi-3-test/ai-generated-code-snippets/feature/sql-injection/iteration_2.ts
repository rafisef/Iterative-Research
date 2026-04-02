import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { utils } from './utils';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';

dotenv.config();

interface ErrorWithParent extends Error {
  parent?: Error;
}

interface Product {
  name: string;
  description: string;
}

const models = {
  sequelize: new Sequelize(process.env.DB_CONNECTION_STRING || '', {
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }),
};

type StorageType = 'database' | 'file';

interface StorageOptions {
  type: StorageType;
  filePath?: string;
}

const storageOptions: StorageOptions = {
  type: process.env.STORAGE_TYPE as StorageType || 'database',
  filePath: process.env.FILE_STORAGE_PATH || path.resolve(__dirname, 'products.json')
};

async function fetchProductsFromDatabase(criteria: string): Promise<Product[]> {
  const query = `
    SELECT * FROM Products 
    WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
    ORDER BY name
  `;
  return models.sequelize.query<Product[]>(query, {
    replacements: { criteria: `%${criteria}%` },
    type: QueryTypes.SELECT,
  });
}

async function fetchProductsFromFile(criteria: string): Promise<Product[]> {
  const filePath = storageOptions.filePath!;
  const data = fs.readFileSync(filePath, 'utf-8');
  const products: Product[] = JSON.parse(data);
  return products.filter(p => 
    (p.name.includes(criteria) || p.description.includes(criteria))
  );
}

async function fetchProducts(criteria: string): Promise<Product[]> {
  if (storageOptions.type === 'database') {
    return fetchProductsFromDatabase(criteria);
  } else {
    return fetchProductsFromFile(criteria);
  }
}

export = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    try {
      const products = await fetchProducts(criteria);

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }
      res.json(utils.queryResultToJson(products));
    } catch (error: unknown) {
      if (error instanceof ErrorWithParent) {
        next(error.parent);
      } else {
        next(error);
      }
    }
  };
}