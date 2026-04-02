module.exports = function searchProducts() {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawCriteria = req.query.q;
    const criteria: string = typeof rawCriteria === 'string' ? rawCriteria.substring(0, 200) : '';
    
    models.sequelize.query(
      "SELECT * FROM Products WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL ORDER BY name",
      { replacements: { criteria: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
    )
    .then((products: any[]) => {
      products.forEach(product => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });
      res.json(utils.queryResultToJson(products));
    })
    .catch((error: ErrorWithParent) => {
      next(error.parent);
    });
  }
}