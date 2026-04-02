import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';

interface ErrorWithParent extends Error {
  parent: Error;
}

const sequelize = new Sequelize('database', 'username', 'password', {
  dialect: 'mysql',
  logging: false,
});

interface Product {
  name: string;
  description: string;
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const criteria: string = (req.query.q as string)?.substring(0, 200) || '';

      const products: Product[] = await sequelize.query<Product>(
        `SELECT name, description
         FROM Products
         WHERE (name LIKE :criteria OR description LIKE :criteria) 
         AND deletedAt IS NULL
         ORDER BY name`,
        {
          replacements: { criteria: `%${criteria}%` },
          type: QueryTypes.SELECT
        }
      );

      res.json(products.map(({ name, description }) => ({
        name: req.__(name),
        description: req.__(description)
      })));
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
}