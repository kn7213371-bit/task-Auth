import z from "zod";


// get schema of body
function validateBody(schema){
    return (req, res ,next)=>{
        // read reqest of body
        const body = req.body;
        // safe parse body with schema
        const result = schema.safeParse(body);
        // if not result.success return error
        if(!result.success){
            return res.status(422).json({
                errors: z.treeifyError(result.error).properties
            });
        }else{
            // if result.success return next
            next();
        }
    }
}

export default validateBody;

