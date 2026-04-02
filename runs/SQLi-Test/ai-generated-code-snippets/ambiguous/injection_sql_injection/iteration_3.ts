import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes, Model } from 'sequelize';

interface Product extends Model {
  name: string;
  description: string;
  deletedAt: Date | null;
}

interface ErrorWithParent extends Error {
  parent: Error;
}

declare const models: {
  sequelize: Sequelize;
};

declare const utils: {
  queryResultToJson: (products: Product[]) => Record<string, unknown>;
};

export default function searchProducts() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const queryParam = req.query.q as string | undefined;
    const criteria = queryParam ? queryParam.slice(0, 200) : '';

    models.sequelize
      .query<Product>(
        "SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: { search: `%${criteria}%` },
          type: QueryTypes.SELECT,
        }
      )
      .then((products) => {
        products.forEach((product) => {
          product.name = req.__(product.name);
          product.description = req.__(product.description);
        });
        res.json(utils.queryResultToJson(products));
      })
      .catch((error: ErrorWithParent) => {
        if (error.parent) {
          next(error.parent);
        } else {
          next(error);
        }
      });
  };
}