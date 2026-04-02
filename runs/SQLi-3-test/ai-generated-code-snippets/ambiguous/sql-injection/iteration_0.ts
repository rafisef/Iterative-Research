import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { ErrorWithParent } from './types'; // Assuming there is a custom error type
import { utils } from './utils';
import models from './models'; // Assuming models is properly imported

type Product = {
  name: string;
  description: string;
  deletedAt: Date | null;
};

export const searchProducts = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: string = typeof req.query.q === 'string' ? req.query.q : '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    const query = `
      SELECT * FROM Products 
      WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
      ORDER BY name
    `;

    models.sequelize.query<Product>(query, {
      replacements: { criteria: `%${criteria}%` },
      type: QueryTypes.SELECT,
    })
      .then((products: Product[]) => {
        products.forEach(product => {
          product.name = req.__(product.name);
          product.description = req.__(product.description);
        });
        res.json(utils.queryResultToJson(products));
      })
      .catch((error: ErrorWithParent) => {
        next(error.parent);
      });
  };
};