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
      const rawCriteria = req.query.q as string | undefined;
      const criteria: string = rawCriteria ? rawCriteria.substring(0, 200) : '';

      const query = `
        SELECT name, description
        FROM Products
        WHERE (name LIKE :criteria OR description LIKE :criteria) 
        AND deletedAt IS NULL
        ORDER BY name
      `;

      const products: Product[] = await sequelize.query<Product>(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT
      });

      const translatedProducts = products.map(product => ({
        name: req.__(product.name),
        description: req.__(product.description)
      }));

      res.json(translatedProducts);
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
}