import { backend } from '@/lib/backend';
import { validId } from '@/lib/boundary.mjs';
export const dynamic = 'force-dynamic';
export async function GET(request: Request, context: {params: Promise<{id: string}>}) {
  const {id} = await context.params;
  if (!validId(id)) return Response.json({detail: 'Invalid identifier.'}, {status: 400});
  return backend(request, `/v1/findings/${id}/spec`);
}
