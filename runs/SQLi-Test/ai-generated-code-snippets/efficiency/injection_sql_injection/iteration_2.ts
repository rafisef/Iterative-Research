import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';

interface ErrorWithParent extends Error {
  parent: Error;
}

const sequelize = new Sequelize('database', 'username', 'password', {
  dialect: 'mysql',
});

type Product = {
  name: string;
  description: string;
  [key: string]: any;
};

const queryResultToJson = (results: any[]): any => results;

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q as string | undefined;
      const criteria: string = rawCriteria ? rawCriteria.substring(0, 200) : '';
      const products: Product[] = await sequelize.query<Product>(
        "SELECT * FROM Products WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL ORDER BY name",
        { replacements: { criteria: `%${criteria}%` }, type: QueryTypes.SELECT }
      );

      const translatedProducts = products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description),
      }));

      res.json(queryResultToJson(translatedProducts));
    } catch (error: any) {
      next((error as ErrorWithParent).parent);
    }
  };
}