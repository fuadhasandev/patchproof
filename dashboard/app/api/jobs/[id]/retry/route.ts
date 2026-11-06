import { backend } from '@/lib/backend';
import { validId } from '@/lib/boundary.mjs';
export async function POST(request: Request, context: {params: Promise<{id:string}>}) {
  const {id}=await context.params;
  if (!validId(id)) return Response.json({detail:'Invalid identifier.'},{status:400});
  return backend(request, `/v1/jobs/${id}/retry`);
}
