import { backend } from '@/lib/backend';
import { validId, historyQuery } from '@/lib/boundary.mjs';
export const dynamic = 'force-dynamic';
export async function POST(request: Request, context: {params: Promise<{id: string}>}) {
  const {id} = await context.params;
  if (!validId(id)) return Response.json({detail: 'Invalid identifier.'}, {status: 400});
  return backend(request, `/v1/findings/${id}/rechecks`);
}

export async function GET(request: Request, context: {params: Promise<{id:string}>}) {
  const {id} = await context.params;
  const query = historyQuery(new URL(request.url).search);
  if (!validId(id) || query === null) return Response.json({detail:'Invalid identifier or pagination.'},{status:422});
  return backend(request, `/v1/findings/${id}/rechecks` + query);
}
