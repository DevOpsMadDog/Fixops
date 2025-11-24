declare module 'react-cytoscapejs' {
  import { Component } from 'react'
  import Cytoscape from 'cytoscape'

  interface CytoscapeElement {
    data: {
      id: string
      label?: string
      source?: string
      target?: string
      [key: string]: unknown
    }
  }

  interface CytoscapeStylesheet {
    selector: string
    style: Record<string, unknown>
  }

  interface CytoscapeLayout {
    name: string
    [key: string]: unknown
  }

  interface CytoscapeComponentProps {
    elements: CytoscapeElement[]
    style?: React.CSSProperties
    stylesheet?: CytoscapeStylesheet[]
    layout?: CytoscapeLayout
    cy?: (cy: Cytoscape.Core) => void
    [key: string]: unknown
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}
