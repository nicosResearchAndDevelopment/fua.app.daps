const
    {Model, Resource, Property} = require('@nrd/fua.module.space'),
    /** @type {fua.module.space.Model} */
    model                       = new Model();

model.set('daps:DapsServer', class DapsServer extends Resource {

    // TODO

});

model.set('daps:DapsSubject', class DapsSubject extends Resource {

    // TODO

});

module.exports = model.finish();
