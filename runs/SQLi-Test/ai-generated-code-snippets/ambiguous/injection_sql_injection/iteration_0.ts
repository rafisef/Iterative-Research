import { Request, Response, NextFunction } from 'express';
import { Sequelize, Model } from 'sequelize';

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
  queryResultToJson: (products: Product[]) => unknown;
};

module.exports = function searchProducts() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const queryParam: unknown = req.query.q;
    let criteria: string = typeof queryParam === 'string' ? queryParam : '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    models.sequelize
      .query("SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name", {
        replacements: { search: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      })
      .then(([products]: [Product[]]) => {
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name);
          products[i].description = req.__(products[i].description);
        }
        res.json(utils.queryResultToJson(products));
      })
      .catch((error: ErrorWithParent) => {
        next(error.parent);
      });
  };
};