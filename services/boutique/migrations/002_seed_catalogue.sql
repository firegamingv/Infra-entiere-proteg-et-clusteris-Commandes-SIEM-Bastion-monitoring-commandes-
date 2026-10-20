-- Catalogue de démonstration (mobilier OSTRAL). Prix en centimes d'euro.
INSERT INTO products (sku, name, description, price_cents, weight_grams) VALUES
  ('OST-CHA-001', 'Chaise Lune',          'Chaise en chêne massif, assise tissu lin.',              8900,  5500),
  ('OST-TAB-002', 'Table Fjord 180',      'Table à manger en frêne, 6 à 8 couverts.',             64900, 42000),
  ('OST-CAN-003', 'Canapé Brume 3 places','Canapé déhoussable, velours côtelé gris.',             119900, 68000),
  ('OST-BIB-004', 'Bibliothèque Strate',  'Étagère modulable 5 niveaux, métal et noyer.',          34900, 31000),
  ('OST-LIT-005', 'Lit Aube 160',         'Lit double avec tête de lit capitonnée, sommier inclus.', 79900, 55000),
  ('OST-LAM-006', 'Lampadaire Halo',      'Lampadaire arc en laiton brossé, LED intégrée.',        15900,  9000)
ON CONFLICT (sku) DO NOTHING;
