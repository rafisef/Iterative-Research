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
  [key: string]: any;
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q as string | undefined;
      const criteria: string = rawCriteria ? rawCriteria.substring(0, 200) : '';

      const products: Product[] = await sequelize.query<Product>(
        "SELECT name, description FROM Products WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL ORDER BY name",
        { replacements: { criteria: `%${criteria}%` }, type: QueryTypes.SELECT }
      );

      const translatedProducts = products.map(product => {
        const { name, description, ...rest } = product;
        return {
          ...rest,
          name: req.__(name),
          description: req.__(description),
        };
      });

      res.json(translatedProducts);
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
}