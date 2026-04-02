module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const criteria: string = req.query.q ? String(req.query.q).substring(0, 200) : '';
      const query = `
        SELECT * FROM Products 
        WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
        ORDER BY name
      `;
      const [products]: Array<{ name: string; description: string }> = await models.sequelize.query(query, {
        replacements: { criteria: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      });

      res.json(utils.queryResultToJson(products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description)
      }))));
    } catch (error: any) {
      next(error?.parent || error);
    }
  };
}