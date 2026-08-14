// ==========================================
// CONTENIDO PARA LA APK
// ==========================================

if (
  req.method === 'GET' &&
  p === '/content'
) {
  const auth =
    requireUser(
      req,
      db
    );

  if (!auth) {
    return json(
      res,
      401,
      {
        error:
          'No autorizado'
      }
    );
  }

  let type =
    cleanText(
      url.searchParams.get(
        'type'
      ) || '',
      30
    ).toUpperCase();

  // La APK solicita LIVE para TV en vivo,
  // mientras el panel administrador guarda esos elementos como TV.
  if (type === 'LIVE') {
    type = 'TV';
  }

  let items =
    db.content.filter(
      c =>
        c.active !==
        false
    );

  if (type) {
    items =
      items.filter(
        c =>
          String(
            c.type
          ).toUpperCase() ===
          type
      );
  }

  saveDb(db);

  return json(
    res,
    200,
    items.map(
      contentDto
    )
  );
}
