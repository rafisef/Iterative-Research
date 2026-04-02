module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const criteria: string = req.query.q && req.query.q !== 'undefined' ? String(req.query.q).substring(0, 200) : '';
      const query = `
        SELECT * FROM Products 
        WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
        ORDER BY name
      `;
      const [products]: any[] = await models.sequelize.query(query, {
        replacements: { criteria: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      });

      products.forEach((product: { name: string; description: string }) => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });

      res.json(utils.queryResultToJson(products));
    } catch (error: any) {
      next(error.parent);
    }
  };
}