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

const dbConnectionString: string = process.env.DB_CONNECTION_STRING || '';
const poolMax: number = parseInt(process.env.DB_POOL_MAX || '10', 10);
const poolMin: number = parseInt(process.env.DB_POOL_MIN || '0', 10);
const poolAcquire: number = parseInt(process.env.DB_POOL_ACQUIRE || '30000', 10);
const poolIdle: number = parseInt(process.env.DB_POOL_IDLE || '10000', 10);

const models = {
  sequelize: new Sequelize(dbConnectionString, {
    pool: {
      max: poolMax,
      min: poolMin,
      acquire: poolAcquire,
      idle: poolIdle
    }
  }),
};

type StorageType = 'database' | 'file';

interface StorageOptions {
  type: StorageType;
  filePath?: string;
}

const storageOptions: StorageOptions = {
  type: (process.env.STORAGE_TYPE as StorageType) || 'database',
  filePath: process.env.FILE_STORAGE_PATH || path.resolve(__dirname, 'products.json')
};

async function fetchProductsFromDatabase(criteria: string, transaction?: any): Promise<Product[]> {
  const query = `
    SELECT * FROM Products 
    WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
    ORDER BY name
  `;
  return models.sequelize.query<Product[]>(query, {
    replacements: { criteria: `%${criteria}%` },
    type: QueryTypes.SELECT,
    transaction
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

async function fetchProducts(criteria: string, transaction?: any): Promise<Product[]> {
  if (storageOptions.type === 'database') {
    return fetchProductsFromDatabase(criteria, transaction);
  } else {
    return fetchProductsFromFile(criteria);
  }
}

export = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    const session = await models.sequelize.startUnmanagedTransaction();

    try {
      const products = await fetchProducts(criteria, session);

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }
      res.json(utils.queryResultToJson(products));
      await session.commit();
    } catch (error: unknown) {
      await session.rollback();
      if (error instanceof ErrorWithParent) {
        next(error.parent);
      } else {
        next(error);
      }
    }
  };
}