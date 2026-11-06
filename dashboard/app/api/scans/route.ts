import { backend } from '@/lib/backend';
import { historyQuery } from '@/lib/boundary.mjs';
export const dynamic = 'force-dynamic';
export function POST(request: Request) { return backend(request, '/v1/scans'); }
export function GET(request: Request) {
  const query = historyQuery(new URL(request.url).search);
  if (query === null) return Response.json({detail:'Invalid pagination.'}, {status:422});
  return backend(request, '/v1/scans' + query);
}
