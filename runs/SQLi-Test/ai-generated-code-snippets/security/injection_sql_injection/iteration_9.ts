import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes, Options } from 'sequelize';
import { RequestHandler } from 'express';

interface ErrorWithParent extends Error {
  parent?: Error;
}

interface Product {
  name: string;
  description: string;
}

const sequelizeOptions: Options = {
  dialect: 'postgres',
  host: 'localhost',
  username: 'username',
  password: 'password',
  database: 'database',
  logging: false,
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  }
};

const models = {
  sequelize: new Sequelize(sequelizeOptions)
};

function isValidString(input: unknown): input is string {
  return typeof input === 'string';
}

const searchProducts: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const query = req.query.q;
    const criteria: string = isValidString(query) ? query : '';
    const truncatedCriteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);
    const sanitizedCriteria = `%${truncatedCriteria.replace(/[%_]/g, '\\$&')}%`;

    const products: Product[] = await models.sequelize.query<Product>(
      'SELECT name, description FROM Products WHERE ((name LIKE :criteria ESCAPE \'\\\' OR description LIKE :criteria ESCAPE \'\\\') AND deletedAt IS NULL) ORDER BY name',
      {
        replacements: { criteria: sanitizedCriteria },
        type: QueryTypes.SELECT,
        raw: true
      }
    );

    for (const product of products) {
      product.name = req.__(product.name);
      product.description = req.__(product.description);
    }

    res.json(products);
  } catch (error: unknown) {
    const err = error as ErrorWithParent;
    if (err.parent) {
      next(err.parent);
    } else {
      next(err);
    }
  }
};

export = searchProducts;