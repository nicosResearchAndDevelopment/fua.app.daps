const
    {Model, Resource, Property} = require('@nrd/fua.module.space'),
    /** @type {fua.module.space.Model} */
    model                       = new Model();

// model.set('ids:DAPS', class DapsServer extends Resource {
//     // TODO
// });

model.set('ids:ConnectorCatalog', class DapsSubject extends Resource {
    // TODO
});

model.set('ids:Connector', class DapsSubject extends Resource {
    // TODO
});

module.exports = model.finish();
