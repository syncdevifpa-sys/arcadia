-- Aplicar somente no PostgreSQL do Preview do Google Drive.
ALTER TABLE public.documento_itens ADD COLUMN IF NOT EXISTS drive_file_id text;
